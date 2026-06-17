using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Cda.Core.Cpu;
using Cda.Core.Model;
using Cda.Core.Pe;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Captures a DLL's calls from the moment it loads — including its
    /// DllMain(DLL_PROCESS_ATTACH) — by launching a host process under a debugger
    /// and instrumenting the DLL while the loader is stopped at the module-load
    /// event, BEFORE the loader calls DllMain.
    ///
    /// Why a debugger rather than the suspended-launch trick used for EXEs: a DLL
    /// has no process of its own and isn't mapped until some host calls
    /// LoadLibrary. Windows delivers a LOAD_DLL_DEBUG_EVENT when the image is
    /// mapped, which for a dynamically loaded DLL precedes its DllMain. At that
    /// instant every thread is frozen, so we discover the DLL's functions (from
    /// its on-disk image, rebased to the actual load address) and arm entry hooks,
    /// then let the loader continue into the now-instrumented DllMain.
    ///
    /// All Win32 debug calls (CreateProcess-with-DEBUG, WaitForDebugEvent,
    /// ContinueDebugEvent, DebugActiveProcessStop) must be made from the single
    /// thread that created the debuggee, so the entire loop lives on a dedicated
    /// background thread. Progress and failures are reported via <see cref="Log"/>
    /// so the UI's diagnostic log shows exactly what happened.
    /// </summary>
    public sealed class DebugLoadCapture : IDisposable
    {
        /// <summary>Everything the UI needs once the target DLL is hooked.</summary>
        public sealed class HookedDll
        {
            public int Pid;
            public bool Is64Bit;
            public CaptureSession Session = null!;
            public TraceDataset Dataset = null!;
            public ModuleInfo Module = null!;
            public int Instrumented;
            public int Skipped;
            public string? FirstError;
        }

        public event Action<string>? Log;
        public event Action<HookedDll>? DllHooked;
        public event Action? TargetExited;

        private readonly string _hostPath;
        private readonly string _commandLine;
        private readonly string _dllPath;
        private readonly string _dllName;
        private readonly int _maxFunctions;
        private readonly int _candidatePool;
        private readonly int _bufferRecords;
        private readonly bool _disableAslr;

        private Thread? _thread;
        private volatile bool _stop;
        private int _pid;
        private bool _hooked;
        private bool _loaderBpSeen; // the loader breakpoint has been consumed

        public DebugLoadCapture(string hostPath, string commandLine, string dllPath,
            int maxFunctions, int candidatePool, int bufferRecords, bool disableAslr = false)
        {
            _hostPath = hostPath;
            _commandLine = commandLine;
            _dllPath = dllPath;
            _dllName = Path.GetFileName(dllPath);
            _maxFunctions = maxFunctions;
            _candidatePool = candidatePool;
            _bufferRecords = bufferRecords;
            _disableAslr = disableAslr;
        }

        public void Start()
        {
            _thread = new Thread(Run) { IsBackground = true, Name = "CDA debug loop" };
            _thread.Start();
        }

        /// <summary>Ask the loop to detach from the host and end (non-blocking).</summary>
        public void Stop() => _stop = true;

        public void Dispose() => Stop();

        private void Run()
        {
            // DEBUG_EVENT is union-heavy and laid out differently on x86/x64; rather
            // than marshal the union we read the fields we need by offset from a raw
            // buffer. The union starts after the 3-DWORD header, 8-byte aligned on
            // x64 (offset 16) and 4-byte aligned on x86 (offset 12).
            IntPtr evt = Marshal.AllocHGlobal(4096);
            int U = IntPtr.Size == 8 ? 16 : 12;
            try
            {
                string? workDir = Path.GetDirectoryName(_hostPath);
                bool ok = NativeMethods.CreateProcessGuarded(
                    _hostPath, _commandLine, NativeMethods.DEBUG_ONLY_THIS_PROCESS, workDir,
                    _disableAslr, hideWindow: false, out var pi);
                if (!ok)
                {
                    Log?.Invoke($"debug launch failed (error {Marshal.GetLastWin32Error()})");
                    return;
                }
                _pid = (int)pi.dwProcessId;
                NativeMethods.CloseHandle(pi.hThread);
                NativeMethods.CloseHandle(pi.hProcess);

                // If our app dies, don't take the host down abruptly with it.
                NativeMethods.DebugSetProcessKillOnExit(false);
                Log?.Invoke($"host launched under debugger (pid {_pid}{(_disableAslr ? ", ASLR disabled" : "")}); waiting for {_dllName} to load…");

                while (true)
                {
                    if (!NativeMethods.WaitForDebugEvent(evt, 200))
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err == NativeMethods.ERROR_SEM_TIMEOUT)
                        {
                            if (_stop) { Detach(); break; }
                            continue;
                        }
                        Log?.Invoke($"WaitForDebugEvent error {err}");
                        break;
                    }

                    uint code = (uint)Marshal.ReadInt32(evt, 0);
                    uint evtPid = (uint)Marshal.ReadInt32(evt, 4);
                    uint evtTid = (uint)Marshal.ReadInt32(evt, 8);
                    uint cont = NativeMethods.DBG_CONTINUE;

                    switch (code)
                    {
                        case NativeMethods.CREATE_PROCESS_DEBUG_EVENT:
                            // CREATE_PROCESS_DEBUG_INFO.hFile is the first field.
                            CloseEventFile(Marshal.ReadIntPtr(evt, U));
                            break;

                        case NativeMethods.LOAD_DLL_DEBUG_EVENT:
                        {
                            IntPtr hFile = Marshal.ReadIntPtr(evt, U);                  // LOAD_DLL_DEBUG_INFO.hFile
                            IntPtr baseOfDll = Marshal.ReadIntPtr(evt, U + IntPtr.Size); // .lpBaseOfDll
                            try
                            {
                                if (!_hooked)
                                {
                                    string loaded = ResolvePath(hFile);
                                    if (loaded.Length > 0 &&
                                        string.Equals(Path.GetFileName(loaded), _dllName, StringComparison.OrdinalIgnoreCase))
                                    {
                                        HookTargetDll((ulong)baseOfDll.ToInt64());
                                        _hooked = true;
                                    }
                                }
                            }
                            catch (Exception ex) { Log?.Invoke("hook-on-load failed: " + ex.Message); }
                            finally { CloseEventFile(hFile); }
                            break;
                        }

                        case NativeMethods.EXCEPTION_DEBUG_EVENT:
                        {
                            uint exCode = (uint)Marshal.ReadInt32(evt, U); // EXCEPTION_RECORD.ExceptionCode

                            // The first breakpoint is the loader's — swallow it. A
                            // later int3 is real (a splice that ran into 0xCC padding,
                            // or the program's own debug-break / anti-tamper on the
                            // patched code); report it with the faulting module+RVA and
                            // hand it back to the program rather than swallowing it.
                            bool isBp = exCode == NativeMethods.EXCEPTION_BREAKPOINT ||
                                        exCode == NativeMethods.STATUS_WX86_BREAKPOINT;
                            bool loaderBp = isBp && !_loaderBpSeen;
                            if (loaderBp) _loaderBpSeen = true;

                            if (!loaderBp && (DebugExceptionInfo.IsCrash(exCode) || isBp))
                            {
                                string? line = DebugExceptionInfo.Format(evt, U, exCode, (int)evtPid);
                                if (line != null) Log?.Invoke(line);
                            }

                            cont = loaderBp ? NativeMethods.DBG_CONTINUE
                                            : NativeMethods.DBG_EXCEPTION_NOT_HANDLED;
                            break;
                        }

                        case NativeMethods.EXIT_PROCESS_DEBUG_EVENT:
                            NativeMethods.ContinueDebugEvent(evtPid, evtTid, NativeMethods.DBG_CONTINUE);
                            Log?.Invoke("host exited.");
                            TargetExited?.Invoke();
                            return;
                    }

                    NativeMethods.ContinueDebugEvent(evtPid, evtTid, cont);

                    if (_stop) { Detach(); break; }
                }
            }
            catch (Exception ex)
            {
                Log?.Invoke("debug loop error: " + ex.Message);
            }
            finally
            {
                Marshal.FreeHGlobal(evt);
            }
        }

        private void Detach()
        {
            try { NativeMethods.DebugActiveProcessStop((uint)_pid); } catch { /* best effort */ }
            Log?.Invoke("detached from host (left running).");
        }

        private static void CloseEventFile(IntPtr h)
        {
            if (h != IntPtr.Zero && h != NativeMethods.INVALID_HANDLE_VALUE)
                NativeMethods.CloseHandle(h);
        }

        private static string ResolvePath(IntPtr hFile)
        {
            if (hFile == IntPtr.Zero || hFile == NativeMethods.INVALID_HANDLE_VALUE) return "";
            char[] buf = new char[600];
            uint n = NativeMethods.GetFinalPathNameByHandleW(hFile, buf, (uint)buf.Length, 0);
            if (n == 0 || n >= buf.Length) return "";
            return new string(buf, 0, (int)n);
        }

        // The target is stopped at the module-load event: discover the DLL's
        // functions from its on-disk image (rebased to the actual load base, since
        // direct calls are relocation-invariant) and arm entry hooks before the
        // loader runs DllMain. Memory writes go through CaptureSession's own handle;
        // the brief extra thread-suspend it does is balanced before we continue.
        private void HookTargetDll(ulong dllBase)
        {
            byte[] bytes = File.ReadAllBytes(_dllPath);
            var pe = PeImage.FromFile(bytes);
            var arch = CpuArchitectures.For(pe.Is64Bit);

            var rawFuncs = new List<TracedFunction>();
            var rawEdges = new List<(ulong Site, ulong Target)>();
            CallSiteScanner.ScanFileImage(bytes, pe, arch, rawFuncs, rawEdges, maxEdges: 20000);

            ulong delta = unchecked(dllBase - pe.PreferredImageBase);
            var funcs = new List<TracedFunction>(rawFuncs.Count);
            foreach (var f in rawFuncs)
                funcs.Add(new TracedFunction(unchecked(f.Address + delta), dllBase, f.Name));
            var edges = new List<(ulong Site, ulong Target)>(rawEdges.Count);
            foreach (var (s, t) in rawEdges) edges.Add((unchecked(s + delta), unchecked(t + delta)));

            Log?.Invoke($"{_dllName} mapped at 0x{dllBase:X}: {funcs.Count} functions, {edges.Count} call sites");

            var candidates = StartupPlan.Candidates(funcs, edges, skipTop: 16, max: _candidatePool);
            var session = CaptureSession.Start(_pid, candidates, _maxFunctions, _bufferRecords,
                out int instrumented, out int skipped, out string? firstError);
            Log?.Invoke($"DllMain trace: instrumented={instrumented} skipped={skipped} firstError={firstError ?? "(none)"}");

            var module = new ModuleInfo(_dllName, dllBase, pe.SizeOfImage, _dllPath);
            var ds = new TraceDataset { TimeStart = 0, TimeEnd = 1 };
            ds.Modules.Add(module);
            ds.Functions.AddRange(funcs);
            int en = Math.Max(1, edges.Count);
            for (int i = 0; i < edges.Count; i++)
                ds.Records.Add(new CallRecord((double)i / en, edges[i].Site, edges[i].Target));

            DllHooked?.Invoke(new HookedDll
            {
                Pid = _pid,
                Is64Bit = pe.Is64Bit,
                Session = session,
                Dataset = ds,
                Module = module,
                Instrumented = instrumented,
                Skipped = skipped,
                FirstError = firstError,
            });
        }
    }
}
