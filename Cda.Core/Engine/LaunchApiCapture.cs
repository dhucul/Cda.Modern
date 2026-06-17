using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Cda.Core.Model;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Captures the Windows-API calls a program makes <b>from its very first
    /// instruction</b> — by launching it under a debugger and hooking its imported
    /// APIs at the initial loader breakpoint, BEFORE the program's entry point runs.
    ///
    /// Why this exists: <see cref="ApiImportScanner"/> + <see cref="CaptureSession"/>
    /// can already hook a program's imports, but only on an ALREADY-RUNNING process
    /// you attach to (see MainWindow.OnCaptureApi / OnCaptureIat). By the time you
    /// attach, the program has finished its startup and made the very API calls you
    /// wanted to see, so the trace shows zero calls. This path closes that gap.
    ///
    /// Why a debugger rather than the suspended-launch trick the EXE startup trace
    /// uses: at CREATE_SUSPENDED the Windows loader has not run, so kernel32/user32/…
    /// are not mapped yet and the import-address table (IAT) is not bound — there is
    /// nothing to resolve or hook. Launching under a debugger, the loader runs to
    /// completion (all static dependencies mapped, their DllMains called, the IAT
    /// bound) and then issues the initial breakpoint, which the debugger receives
    /// BEFORE the program's entry point executes. That instant — every thread frozen
    /// at the breakpoint, imports fully bound, no app code run yet — is exactly when
    /// we discover the imports and arm the hooks.
    ///
    /// Three surfaces / mechanisms:
    ///   * <see cref="HookMode.Inline"/> splices the resolved API entry points the
    ///     program IMPORTS (like "Capture Windows API") — the most complete capture
    ///     of its calls out to the OS;
    ///   * <see cref="HookMode.Iat"/> overwrites the import-table slots (like
    ///     "Capture imports (IAT)") — writes only to data, never .text, so an
    ///     anti-tamper target that checksums its own code is captured cleanly;
    ///   * <see cref="HookMode.Exports"/> splices the functions the program's own
    ///     modules EXPORT (their public surface — see <see cref="ExportScanner"/>),
    ///     capturing calls IN to the app's own libraries from startup.
    ///
    /// All Win32 debug calls must be made from the one thread that created the
    /// debuggee, so the whole loop lives on a dedicated background thread; progress
    /// and faults are reported via <see cref="Log"/>. After the hooks are armed the
    /// loop keeps pumping (like <see cref="DebugLoadCapture"/>) so a hook-induced
    /// fault is reported live and process exit is detected; the ring is drained by
    /// the UI poll loop through the session's own handle, concurrently.
    /// </summary>
    public sealed class LaunchApiCapture : IDisposable
    {
        public enum HookMode { Inline, Iat, Exports }

        /// <summary>Everything the UI needs once the launched target's imports are hooked.</summary>
        public sealed class HookedApis
        {
            public int Pid;
            public bool Is64Bit;
            public HookMode Mode;
            public CaptureSession Session = null!;
            public TraceDataset Dataset = null!;   // Modules = the OS DLLs, Functions = the API entries
            public ModuleMap ModuleMap = null!;    // full map (app + OS) for resolving callers and callees
            public int Instrumented;
            public int Skipped;
            public string? FirstError;
            public int DistinctApis;               // distinct resolved API entries hooked/listed
            public int SlotCount;                  // IAT mode: number of import slots
            public int ApiModules;                 // distinct OS modules the entries live in
            public int ScannedModules;             // app modules whose imports were scanned
            public int ExcludedHot;
            public int SkippedForwarders;          // exports mode: forwarder exports dropped
            public int SkippedLargeModules;
            public bool Trimmed;                   // capped to maxFunctions
        }

        public event Action<string>? Log;
        public event Action<HookedApis>? Hooked;
        public event Action? TargetExited;

        /// <summary>
        /// Raised (with a reason) when the loader breakpoint was reached but nothing
        /// could be hooked — discovery found no matching surface, or the hook attempt
        /// threw. The target keeps running un-instrumented; the UI uses this to tear
        /// the (now purposeless) debug loop down instead of leaving it attached. Not
        /// raised when hooks were installed, nor when discovery found a surface but
        /// every entry was skipped (that comes through <see cref="Hooked"/> with
        /// Instrumented == 0, which the UI tears down the same way).
        /// </summary>
        public event Action<string>? Aborted;

        private readonly string _exePath;
        private readonly string _commandLine;
        private readonly HookMode _mode;
        private readonly int _maxFunctions;
        private readonly int _bufferRecords;
        private readonly bool _disableAslr;

        private Thread? _thread;
        private volatile bool _stop;
        private int _pid;
        private bool _hooked;
        private bool _loaderBpSeen; // the initial loader breakpoint has been consumed

        public LaunchApiCapture(string exePath, string commandLine, HookMode mode,
            int maxFunctions, int bufferRecords, bool disableAslr = false)
        {
            _exePath = exePath;
            _commandLine = commandLine;
            _mode = mode;
            _maxFunctions = maxFunctions;
            _bufferRecords = bufferRecords;
            _disableAslr = disableAslr;
        }

        public void Start()
        {
            _thread = new Thread(Run) { IsBackground = true, Name = "CDA API launch loop" };
            _thread.Start();
        }

        /// <summary>Ask the loop to detach from the target and end (non-blocking). The
        /// target is left running.</summary>
        public void Stop() => _stop = true;

        public void Dispose() => Stop();

        private void Run()
        {
            // DEBUG_EVENT is union-heavy and laid out differently on x86/x64; read the
            // fields we need by offset (the union starts after the 3-DWORD header,
            // 8-byte aligned on x64 = offset 16, 4-byte aligned on x86 = 12).
            IntPtr evt = Marshal.AllocHGlobal(4096);
            int U = IntPtr.Size == 8 ? 16 : 12;
            try
            {
                string? workDir = Path.GetDirectoryName(_exePath);
                bool ok = NativeMethods.CreateProcessGuarded(
                    _exePath, _commandLine, NativeMethods.DEBUG_ONLY_THIS_PROCESS, workDir,
                    _disableAslr, hideWindow: false, out var pi);
                if (!ok)
                {
                    Log?.Invoke($"launch failed (error {Marshal.GetLastWin32Error()})");
                    TargetExited?.Invoke();
                    return;
                }
                _pid = (int)pi.dwProcessId;
                NativeMethods.CloseHandle(pi.hThread);
                NativeMethods.CloseHandle(pi.hProcess);

                // If our app dies, don't take the target down abruptly with it.
                NativeMethods.DebugSetProcessKillOnExit(false);
                Log?.Invoke($"launched {Path.GetFileName(_exePath)} under debugger (pid {_pid}{(_disableAslr ? ", ASLR disabled" : "")}); " +
                            "waiting for the loader to bind imports, then hooking before the entry point runs…");

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
                            CloseEventFile(Marshal.ReadIntPtr(evt, U)); // CREATE_PROCESS_DEBUG_INFO.hFile
                            break;

                        case NativeMethods.LOAD_DLL_DEBUG_EVENT:
                            CloseEventFile(Marshal.ReadIntPtr(evt, U)); // LOAD_DLL_DEBUG_INFO.hFile
                            break;

                        case NativeMethods.EXCEPTION_DEBUG_EVENT:
                        {
                            uint exCode = (uint)Marshal.ReadInt32(evt, U); // EXCEPTION_RECORD.ExceptionCode

                            // The FIRST breakpoint is the loader's: the loader has just
                            // finished (imports bound, static DllMains run) and broken in
                            // before the entry point. That is our cue to hook the imports.
                            // A LATER int3 is real — a splice that ran into 0xCC padding,
                            // or the program's own debug-break / anti-tamper on the
                            // patched code — report it with the faulting module+RVA and
                            // hand it back to the program rather than swallowing it.
                            bool isBp = exCode == NativeMethods.EXCEPTION_BREAKPOINT ||
                                        exCode == NativeMethods.STATUS_WX86_BREAKPOINT;
                            bool loaderBp = isBp && !_loaderBpSeen;
                            if (loaderBp)
                            {
                                _loaderBpSeen = true;
                                if (!_hooked)
                                {
                                    _hooked = true; // one attempt; don't retry on a later breakpoint
                                    bool armed = false;
                                    try { armed = HookSurface(); }
                                    catch (Exception ex) { Log?.Invoke("startup hook failed: " + ex.Message); }
                                    // Discovery found nothing to hook (or threw): the loop
                                    // would otherwise sit attached to a running target with
                                    // no capture. Tell the UI so it can detach and free up.
                                    if (!armed)
                                        Aborted?.Invoke("startup capture: nothing was hooked — detaching (the target keeps running).");
                                }
                            }
                            else if (DebugExceptionInfo.IsCrash(exCode) || isBp)
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
                            Log?.Invoke("target exited.");
                            TargetExited?.Invoke();
                            return;
                    }

                    NativeMethods.ContinueDebugEvent(evtPid, evtTid, cont);

                    if (_stop) { Detach(); break; }
                }
            }
            catch (Exception ex)
            {
                Log?.Invoke("API launch loop error: " + ex.Message);
            }
            finally
            {
                Marshal.FreeHGlobal(evt);
            }
        }

        private void Detach()
        {
            try { NativeMethods.DebugActiveProcessStop((uint)_pid); } catch { /* best effort */ }
            Log?.Invoke("detached from target (left running).");
        }

        private static void CloseEventFile(IntPtr h)
        {
            if (h != IntPtr.Zero && h != NativeMethods.INVALID_HANDLE_VALUE)
                NativeMethods.CloseHandle(h);
        }

        // The target is frozen at the loader breakpoint: the loader has finished
        // (imports bound, static DllMains run) and the program's entry point has not
        // run. Discover the chosen call surface and arm the hooks before we continue.
        // A separate read-only handle is used for discovery; CaptureSession opens its
        // own write handle.
        // Returns true once it has armed a capture and raised <see cref="Hooked"/>
        // (even if every entry was skipped — Instrumented may be 0); false if it bailed
        // because discovery found no matching surface at all.
        private bool HookSurface()
        {
            ModuleMap map;
            ApiImportScanner.Result? imports = null;
            ApiImportScanner.SlotResult? slots = null;
            ExportScanner.Result? exports = null;
            bool is64;

            using (var probe = TargetProcess.Attach(_pid, forWrite: false))
            {
                is64 = probe.Is64Bit;
                map = new ModuleMap(probe.EnumerateModules());
                switch (_mode)
                {
                    case HookMode.Inline:  imports = ApiImportScanner.Discover(probe, map); break;
                    case HookMode.Iat:     slots   = ApiImportScanner.DiscoverImportSlots(probe, map); break;
                    case HookMode.Exports: exports = ExportScanner.Discover(probe, map); break;
                }
            }

            var ds = new TraceDataset { TimeStart = 0, TimeEnd = 1 };
            CaptureSession session;
            int instrumented, skipped;
            string? firstError;
            var result = new HookedApis { Pid = _pid, Is64Bit = is64, Mode = _mode, ModuleMap = map };

            if (_mode == HookMode.Iat)
            {
                var sr = slots!;
                if (sr.Slots.Count == 0)
                {
                    Log?.Invoke("no import slots found to hook — the target may be managed (.NET), packed, " +
                                "or load its libraries later (delay-load / LoadLibrary).");
                    return false;
                }

                bool trimmed = sr.Slots.Count > _maxFunctions;
                if (trimmed) sr.Slots.RemoveRange(_maxFunctions, sr.Slots.Count - _maxFunctions);

                // Distinct resolved callees → a TracedFunction each, for labels/views.
                var funcs = new List<TracedFunction>();
                var seen = new HashSet<ulong>();
                foreach (var s in sr.Slots)
                    if (seen.Add(s.Target)) funcs.Add(new TracedFunction(s.Target, s.OwnerBase, s.Label));

                var imps = new List<(ulong Slot, ulong Target)>(sr.Slots.Count);
                foreach (var s in sr.Slots) imps.Add((s.SlotVa, s.Target));

                session = CaptureSession.StartIat(_pid, imps, _maxFunctions, _bufferRecords,
                    out instrumented, out skipped, out firstError);

                ds.Modules.AddRange(sr.ApiModules);
                ds.Functions.AddRange(funcs);

                result.DistinctApis = funcs.Count;
                result.SlotCount = sr.Slots.Count;
                result.ApiModules = sr.ApiModules.Count;
                result.ScannedModules = sr.ScannedModules.Count;
                result.ExcludedHot = sr.ExcludedHot;
                result.SkippedLargeModules = sr.SkippedLargeModules;
                result.Trimmed = trimmed;
            }
            else
            {
                // Inline (imports) and Exports both splice resolved entry points and
                // share the same hooking path; they differ only in which functions are
                // discovered and which modules they live in (the OS for imports, the
                // app's own modules for exports).
                List<TracedFunction> funcs;
                List<ModuleInfo> nodeModules;

                if (_mode == HookMode.Inline)
                {
                    var api = imports!;
                    if (api.Functions.Count == 0)
                    {
                        Log?.Invoke("no Windows API imports found to hook — the target may be managed (.NET), " +
                                    "packed, or load its libraries later (delay-load / LoadLibrary).");
                        return false;
                    }
                    funcs = api.Functions;
                    nodeModules = api.ApiModules;
                    result.ApiModules = api.ApiModules.Count;
                    result.ScannedModules = api.ScannedModules.Count;
                    result.ExcludedHot = api.ExcludedHot;
                    result.SkippedLargeModules = api.SkippedLargeModules;
                }
                else // Exports
                {
                    var ex = exports!;
                    if (ex.Functions.Count == 0)
                    {
                        Log?.Invoke("no exported functions found to hook — the target's own modules export " +
                                    "nothing (a typical standalone EXE with no app DLLs), or it is managed (.NET) / packed.");
                        return false;
                    }
                    funcs = ex.Functions;
                    nodeModules = ex.Modules;
                    result.ApiModules = ex.Modules.Count;
                    result.ScannedModules = ex.ScannedModules.Count;
                    result.SkippedForwarders = ex.SkippedForwarders;
                    result.SkippedLargeModules = ex.SkippedLargeModules;
                }

                bool trimmed = funcs.Count > _maxFunctions;
                if (trimmed) funcs.RemoveRange(_maxFunctions, funcs.Count - _maxFunctions);

                var addresses = new List<ulong>(funcs.Count);
                foreach (var f in funcs) addresses.Add(f.Address);

                session = CaptureSession.Start(_pid, addresses, _maxFunctions, _bufferRecords,
                    out instrumented, out skipped, out firstError);

                ds.Modules.AddRange(nodeModules);
                ds.Functions.AddRange(funcs);

                result.DistinctApis = funcs.Count;
                result.Trimmed = trimmed;
            }

            // The function list was capped to _maxFunctions above; drop any module
            // whose every function was trimmed away so the views show no empty groups.
            ds.PruneUnreferencedModules();

            result.Session = session;
            result.Dataset = ds;
            result.Instrumented = instrumented;
            result.Skipped = skipped;
            result.FirstError = firstError;

            Log?.Invoke(DescribeDiscovery(result, instrumented, skipped, firstError));
            Hooked?.Invoke(result);
            return true;
        }

        private static string DescribeDiscovery(HookedApis r, int instrumented, int skipped, string? firstError)
        {
            string tail = $"instrumented={instrumented} skipped={skipped} firstError={firstError ?? "(none)"}";
            switch (r.Mode)
            {
                case HookMode.Iat:
                    return $"IAT discovery (pre-entry): {r.SlotCount} slot(s) over {r.DistinctApis} distinct API(s) across " +
                           $"{r.ApiModules} system module(s), from {r.ScannedModules} app module(s); {tail}";
                case HookMode.Exports:
                    return $"export discovery (pre-entry): {r.DistinctApis} export(s) across {r.ApiModules} app module(s)" +
                           (r.SkippedForwarders > 0 ? $" (skipped {r.SkippedForwarders} forwarder(s))" : "") + $"; {tail}";
                default: // Inline
                    return $"API discovery (pre-entry): {r.DistinctApis} entr{(r.DistinctApis == 1 ? "y" : "ies")} across " +
                           $"{r.ApiModules} system module(s), from {r.ScannedModules} app module(s); {tail}";
            }
        }
    }
}
