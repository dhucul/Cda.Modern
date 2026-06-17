using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Cda.Core.Cpu;
using Cda.Core.Model;
using Cda.Core.Pe;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Launches a target under a debugger with <c>DEBUG_PROCESS</c> — which debugs
    /// the target AND every descendant it spawns — and follows the whole process
    /// tree, instrumenting each process the instant it appears.
    ///
    /// Each process in the tree (root and every child) is hooked at its
    /// CREATE_PROCESS debug event. At that instant the new process is frozen and
    /// its main image is mapped but none of its own code has run yet, so we can
    /// discover its functions from the on-disk image (rebased to the event's
    /// reported load base) and arm a startup trace via the proven
    /// <see cref="CaptureSession"/> path BEFORE letting it continue — exactly the
    /// timing the suspended-launch startup trace relies on. Each hooked process's
    /// ring buffer is drained on a steady cadence from inside the loop; the decoded
    /// records are emitted per process via <see cref="RecordsCaptured"/>, and each
    /// newly instrumented process is announced via <see cref="ProcessHooked"/> with
    /// a dataset the UI can register as a selectable target. Per-process call counts
    /// are also summarized via <see cref="Log"/>. Keeping the single ring reader on
    /// this one loop thread is what makes draining race-free; the UI owns retention
    /// and trimming, so this loop itself stays memory-flat no matter how busy the
    /// tree is.
    ///
    /// Safety: every per-process hook attempt is fully isolated in try/catch — a
    /// failure to instrument one process never stalls it (it just runs
    /// uninstrumented) and never disturbs the rest of the tree. Bitness is gated
    /// (an x86 build won't try to hook a 64-bit child) and the same packed-binary
    /// heuristic used elsewhere skips processes whose real code isn't visible yet.
    /// When the system-skip filter is on (the default), children whose image lives
    /// under the Windows directory (OS helpers like conhost/WerFault) are followed
    /// but not instrumented; the root is always instrumented, even if it lives there.
    ///
    /// As with <see cref="DebugLoadCapture"/>, all Win32 debug calls must come from
    /// the one thread that created the debuggee, and so must the hooking (it must
    /// happen while the process is frozen at its create event). The entire loop —
    /// debug pump, per-process hooking, and polling — therefore lives on a single
    /// dedicated background thread and reports progress via <see cref="Log"/>.
    /// </summary>
    public sealed class ChildFollowCapture : IDisposable
    {
        /// <summary>A process in the followed tree.</summary>
        public sealed class ProcessInfo
        {
            public int Pid;
            public string Path = "";
            public bool IsRoot;
        }

        /// <summary>Everything the UI needs to register a newly hooked process as a target.</summary>
        public sealed class HookedProcess
        {
            public int Pid;
            public bool Is64Bit;
            public TraceDataset Dataset = null!; // modules + functions (+ static call edges)
            public int Instrumented;
            public int Skipped;
            public string? FirstError;
        }

        public event Action<string>? Log;
        public event Action<ProcessInfo>? ProcessStarted;
        public event Action<HookedProcess>? ProcessHooked;           // a process was instrumented
        public event Action<int, List<CallRecord>>? RecordsCaptured; // (pid, decoded records) per drain
        public event Action<int>? ProcessExited;
        public event Action? TreeExited;

        private readonly string _exePath;
        private readonly string _commandLine;
        private readonly int _maxFunctions;
        private readonly int _candidatePool;
        private readonly int _bufferRecords;
        private readonly int _minPreRunFunctions;
        private readonly bool _skipSystem; // don't instrument \Windows\ children (OS helpers)
        private readonly bool _disableAslr; // launch the whole tree with ASLR forced off
        private readonly string _winDir;   // cached Windows dir for the system-image test

        private Thread? _thread;
        private volatile bool _stop;
        private int _rootPid;

        // The cadence (ms) at which hooked processes' ring buffers are drained, and
        // how often a running per-process count summary is logged.
        private const long PollIntervalMs = 150;
        private const long SummaryIntervalMs = 1000;

        // All of the following are touched ONLY on the loop thread (debug events,
        // hooking, and polling all run there), so no locking is needed.
        private readonly HashSet<int> _live = new();                  // live PIDs in the tree
        private readonly HashSet<int> _loaderBp = new();              // pids whose loader breakpoint was consumed
        private readonly Dictionary<int, CaptureSession> _sessions = new(); // hooked PID -> its trace
        private readonly Dictionary<int, long> _counts = new();       // hooked PID -> calls captured
        private long _lastPoll;
        private long _lastSummary;

        public ChildFollowCapture(string exePath, int maxFunctions, int candidatePool,
            int bufferRecords, int minPreRunFunctions, bool skipSystemProcesses = true,
            bool disableAslr = false, string? commandLine = null)
        {
            _exePath = exePath;
            _commandLine = string.IsNullOrEmpty(commandLine) ? "\"" + exePath + "\"" : commandLine!;
            _maxFunctions = maxFunctions;
            _candidatePool = candidatePool;
            _bufferRecords = bufferRecords;
            _minPreRunFunctions = minPreRunFunctions;
            _skipSystem = skipSystemProcesses;
            _disableAslr = disableAslr;
            string win;
            try { win = Environment.GetFolderPath(Environment.SpecialFolder.Windows); }
            catch { win = ""; }
            _winDir = win ?? "";
        }

        public void Start()
        {
            _thread = new Thread(Run) { IsBackground = true, Name = "CDA child-follow loop" };
            _thread.Start();
        }

        /// <summary>
        /// Ask the loop to remove its hooks, detach from the whole tree, and end
        /// (non-blocking). The processes are left running.
        /// </summary>
        public void Stop() => _stop = true;

        public void Dispose() => Stop();

        private void Run()
        {
            // DEBUG_EVENT is union-heavy and laid out differently on x86/x64; read
            // the fields we need by offset (the union starts after the 3-DWORD
            // header, 8-byte aligned on x64 = offset 16, 4-byte aligned on x86 = 12).
            IntPtr evt = Marshal.AllocHGlobal(4096);
            int U = IntPtr.Size == 8 ? 16 : 12;
            try
            {
                string? workDir = Path.GetDirectoryName(_exePath);
                bool ok = NativeMethods.CreateProcessGuarded(
                    _exePath, _commandLine, NativeMethods.DEBUG_PROCESS, workDir,
                    _disableAslr, hideWindow: false, out var pi);
                if (!ok)
                {
                    Log?.Invoke($"launch failed (error {Marshal.GetLastWin32Error()})");
                    TreeExited?.Invoke();
                    return;
                }
                _rootPid = (int)pi.dwProcessId;
                NativeMethods.CloseHandle(pi.hThread);
                NativeMethods.CloseHandle(pi.hProcess);

                // If our app dies, don't take the whole tree down with it.
                NativeMethods.DebugSetProcessKillOnExit(false);
                Log?.Invoke($"following {Path.GetFileName(_exePath)} (pid {_rootPid}{(_disableAslr ? ", ASLR disabled" : "")}) and its children; instrumenting each as it starts…");

                _lastPoll = _lastSummary = Environment.TickCount64;

                while (true)
                {
                    // Drain hooked processes on a steady cadence, independent of the
                    // debug-event flow (a normally-running process emits few events).
                    PollIfDue();

                    if (!NativeMethods.WaitForDebugEvent(evt, (uint)PollIntervalMs))
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err == NativeMethods.ERROR_SEM_TIMEOUT)
                        {
                            if (_stop) { DisposeAllSessions(); DetachAll(); break; }
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
                        {
                            // CREATE_PROCESS_DEBUG_INFO: hFile @U, hProcess @U+ptr,
                            // hThread @U+2*ptr, lpBaseOfImage @U+3*ptr.
                            IntPtr hFile = Marshal.ReadIntPtr(evt, U);
                            ulong imageBase = (ulong)Marshal.ReadIntPtr(evt, U + 3 * IntPtr.Size).ToInt64();
                            string path = Clean(ResolvePath(hFile));
                            CloseEventFile(hFile);

                            bool isRoot = (int)evtPid == _rootPid;
                            _live.Add((int)evtPid);

                            // Optionally leave OS helper processes (conhost, WerFault,
                            // …) uninstrumented — still followed, just not hooked. The
                            // root is always instrumented, even if it lives in \Windows\.
                            bool skipSys = _skipSystem && !isRoot && IsSystemImage(path);
                            Log?.Invoke(isRoot
                                ? $"root process · pid {evtPid} · {path}"
                                : $"child process · pid {evtPid} · {path}" + (skipSys ? " · system image — not instrumented" : ""));
                            ProcessStarted?.Invoke(new ProcessInfo { Pid = (int)evtPid, Path = path, IsRoot = isRoot });

                            // Instrument NOW, while the process is frozen at creation
                            // and before any of its own code has run (unless filtered).
                            if (!skipSys) TryHookProcess((int)evtPid, path, imageBase);
                            break;
                        }

                        case NativeMethods.LOAD_DLL_DEBUG_EVENT:
                            CloseEventFile(Marshal.ReadIntPtr(evt, U)); // release the image file handle
                            break;

                        case NativeMethods.EXCEPTION_DEBUG_EVENT:
                        {
                            uint exCode = (uint)Marshal.ReadInt32(evt, U); // EXCEPTION_RECORD.ExceptionCode

                            // The FIRST breakpoint each process gets is the loader
                            // breakpoint — expected; swallow it silently. A LATER int3
                            // is real: a splice that ran into 0xCC padding, or the
                            // program's own debug-break / anti-tamper reacting to the
                            // patched code. Report those (and every hardware fault)
                            // with the faulting module+RVA so the cause can be pinned,
                            // and hand them back to the program rather than swallowing
                            // them, so its outcome matches reality.
                            bool isBp = exCode == NativeMethods.EXCEPTION_BREAKPOINT ||
                                        exCode == NativeMethods.STATUS_WX86_BREAKPOINT;
                            bool loaderBp = isBp && _loaderBp.Add((int)evtPid);

                            if (!loaderBp && (DebugExceptionInfo.IsCrash(exCode) || isBp))
                            {
                                string? line = DebugExceptionInfo.Format(evt, U, exCode, (int)evtPid);
                                if (line != null)
                                    Log?.Invoke(line + (_sessions.ContainsKey((int)evtPid)
                                        ? "" : " (process not instrumented by CDA)"));
                            }

                            cont = loaderBp ? NativeMethods.DBG_CONTINUE
                                            : NativeMethods.DBG_EXCEPTION_NOT_HANDLED;
                            break;
                        }

                        case NativeMethods.EXIT_PROCESS_DEBUG_EVENT:
                        {
                            _live.Remove((int)evtPid);
                            bool last = _live.Count == 0;

                            // Final drain + remove this process's hooks (best effort —
                            // it is terminating, so reads/writes may already fail).
                            if (_sessions.TryGetValue((int)evtPid, out var sess))
                            {
                                try
                                {
                                    var tail = sess.Poll();
                                    if (tail.Count > 0)
                                    {
                                        _counts[(int)evtPid] = Count((int)evtPid) + tail.Count;
                                        RecordsCaptured?.Invoke((int)evtPid, tail);
                                    }
                                }
                                catch { /* process gone */ }
                                try { sess.Dispose(); } catch { /* process gone */ }
                                _sessions.Remove((int)evtPid);
                                Log?.Invoke($"pid {evtPid} exited · {Count((int)evtPid)} call(s) captured" + (last ? " (tree finished)" : ""));
                            }
                            else
                            {
                                Log?.Invoke($"process exited · pid {evtPid}" + (last ? " (tree finished)" : ""));
                            }

                            ProcessExited?.Invoke((int)evtPid);
                            NativeMethods.ContinueDebugEvent(evtPid, evtTid, NativeMethods.DBG_CONTINUE);
                            if (last) { TreeExited?.Invoke(); return; }
                            if (_stop) { DisposeAllSessions(); DetachAll(); return; }
                            continue; // already continued this event
                        }
                    }

                    NativeMethods.ContinueDebugEvent(evtPid, evtTid, cont);
                    if (_stop) { DisposeAllSessions(); DetachAll(); break; }
                }
            }
            catch (Exception ex)
            {
                Log?.Invoke("child-follow loop error: " + ex.Message);
            }
            finally
            {
                Marshal.FreeHGlobal(evt);
            }
        }

        // Discover the frozen process's functions from its on-disk image, rebase to
        // the event's load base, and arm a startup trace — the same approach as the
        // suspended-launch path, just driven by the create-process debug event. Any
        // failure is contained: the process simply runs uninstrumented.
        private void TryHookProcess(int pid, string imagePath, ulong imageBase)
        {
            try
            {
                if (imageBase == 0) { Log?.Invoke($"pid {pid}: no image base reported; not hooking."); return; }
                if (string.IsNullOrEmpty(imagePath) || imagePath == "(unknown image)")
                { Log?.Invoke($"pid {pid}: image path unknown; not hooking."); return; }

                byte[] bytes;
                try { bytes = File.ReadAllBytes(imagePath); }
                catch (Exception ex) { Log?.Invoke($"pid {pid}: can't read image ({ex.Message}); not hooking."); return; }

                PeImage pe;
                try { pe = PeImage.FromFile(bytes); }
                catch (Exception ex) { Log?.Invoke($"pid {pid}: not a PE image ({ex.Message}); not hooking."); return; }

                // A 32-bit host can't write code a 64-bit target will run. (An x64
                // build instruments both x64 and WOW64 x86 children.)
                if (!Environment.Is64BitProcess && pe.Is64Bit)
                { Log?.Invoke($"pid {pid}: 64-bit target needs an x64 build of CDA — skipped."); return; }

                var arch = CpuArchitectures.For(pe.Is64Bit);
                var rawFuncs = new List<TracedFunction>();
                var rawEdges = new List<(ulong Site, ulong Target)>();
                CallSiteScanner.ScanFileImage(bytes, pe, arch, rawFuncs, rawEdges, maxEdges: 20000);

                if (rawFuncs.Count < _minPreRunFunctions)
                {
                    // Packed/compressed: only the unpacker stub is visible yet, and
                    // hooking it would corrupt the unpacking. Skip — leave it running.
                    Log?.Invoke($"pid {pid}: only {rawFuncs.Count} function(s) visible pre-run (likely packed) — not hooking (would corrupt unpacking).");
                    return;
                }

                ulong delta = unchecked(imageBase - pe.PreferredImageBase);
                var funcs = new List<TracedFunction>(rawFuncs.Count);
                foreach (var f in rawFuncs)
                    funcs.Add(new TracedFunction(unchecked(f.Address + delta), imageBase, f.Name));
                var edges = new List<(ulong Site, ulong Target)>(rawEdges.Count);
                foreach (var (s, t) in rawEdges)
                    edges.Add((unchecked(s + delta), unchecked(t + delta)));

                var candidates = StartupPlan.Candidates(funcs, edges, skipTop: 16, max: _candidatePool);

                // The process is frozen at its create event — pre-loader — so live
                // module enumeration inside Start comes back empty and the
                // entry-point guard would silently fall back to its weak heuristic
                // (hooking non-entry targets → int3 on resume). Pass the main module:
                // its .pdata is readable from the already-mapped image now, so the
                // guard does its authoritative entry check, exactly like the
                // suspended-launch path. (Reused below for the UI dataset.)
                var module = new ModuleInfo(Path.GetFileName(imagePath), imageBase, pe.SizeOfImage, imagePath);

                var session = CaptureSession.Start(pid, candidates, _maxFunctions, _bufferRecords,
                    out int instrumented, out int skipped, out string? firstError,
                    knownModules: new[] { module });

                if (instrumented <= 0)
                {
                    try { session.Dispose(); } catch { /* nothing installed */ }
                    Log?.Invoke($"pid {pid}: no functions could be hooked ({firstError ?? "no candidate"}).");
                    return;
                }

                _sessions[pid] = session;
                _counts[pid] = 0;
                Log?.Invoke($"hooked pid {pid} · {Path.GetFileName(imagePath)} · instrumented={instrumented} skipped={skipped}");

                // Hand the UI a dataset (modules + functions, seeded with the static
                // call edges so its graph has structure) to register as a target.
                var ds = new TraceDataset { TimeStart = 0, TimeEnd = 1 };
                ds.Modules.Add(module);
                ds.Functions.AddRange(funcs);
                int en = Math.Max(1, edges.Count);
                for (int i = 0; i < edges.Count; i++)
                    ds.Records.Add(new CallRecord((double)i / en, edges[i].Site, edges[i].Target));
                ProcessHooked?.Invoke(new HookedProcess
                {
                    Pid = pid, Is64Bit = pe.Is64Bit, Dataset = ds,
                    Instrumented = instrumented, Skipped = skipped, FirstError = firstError,
                });
            }
            catch (Exception ex)
            {
                // A hooking failure must NEVER stall or crash the frozen process or
                // the loop — the process continues uninstrumented.
                Log?.Invoke($"pid {pid}: hook attempt failed ({ex.Message}); process will run uninstrumented.");
            }
        }

        // Drain every hooked process's ring buffer if the cadence is due: fold the
        // per-process counts and emit the decoded records (RecordsCaptured) for the
        // UI to route to its selected target. We don't retain records here — the UI
        // keeps a bounded per-process history — so this loop stays memory-flat.
        private void PollIfDue()
        {
            long now = Environment.TickCount64;
            if (now - _lastPoll < PollIntervalMs) return;
            _lastPoll = now;
            if (_sessions.Count == 0) return;

            bool changed = false;
            foreach (var kv in _sessions)
            {
                List<CallRecord> recs;
                try { recs = kv.Value.Poll(); }
                catch { continue; }
                if (recs.Count > 0)
                {
                    _counts[kv.Key] = Count(kv.Key) + recs.Count;
                    changed = true;
                    RecordsCaptured?.Invoke(kv.Key, recs);
                }
            }

            if (changed && now - _lastSummary >= SummaryIntervalMs)
            {
                _lastSummary = now;
                Log?.Invoke("captured · " + SummaryString());
            }
        }

        // Final drain + remove the hooks from every still-hooked process (so they
        // run clean once we detach). Best effort: the ring read or hook removal can
        // fail if a process is mid-teardown.
        private void DisposeAllSessions()
        {
            foreach (var kv in _sessions)
            {
                try
                {
                    var tail = kv.Value.Poll();
                    if (tail.Count > 0)
                    {
                        _counts[kv.Key] = Count(kv.Key) + tail.Count;
                        RecordsCaptured?.Invoke(kv.Key, tail);
                    }
                }
                catch { /* ignore */ }
                try { kv.Value.Dispose(); } catch { /* ignore */ }
            }
            if (_sessions.Count > 0) Log?.Invoke("captured · " + SummaryString());
            _sessions.Clear();
        }

        // Detach from every process still being debugged, leaving them running.
        private void DetachAll()
        {
            int[] pids = new int[_live.Count];
            _live.CopyTo(pids);
            foreach (int p in pids)
            {
                try { NativeMethods.DebugActiveProcessStop((uint)p); } catch { /* best effort */ }
            }
            Log?.Invoke("detached from the process tree (left running).");
        }

        private long Count(int pid) => _counts.TryGetValue(pid, out long v) ? v : 0;

        // True if <path> is an image under the Windows directory (a system/OS
        // process). Used by the system-skip filter to leave OS helpers (conhost,
        // WerFault, …) followed but uninstrumented.
        private bool IsSystemImage(string path)
        {
            if (_winDir.Length == 0 || string.IsNullOrEmpty(path)) return false;
            return path.StartsWith(_winDir, StringComparison.OrdinalIgnoreCase);
        }

        private string SummaryString()
        {
            var sb = new StringBuilder();
            foreach (var kv in _counts)
            {
                if (sb.Length > 0) sb.Append(" · ");
                sb.Append("pid ").Append(kv.Key).Append(": ").Append(kv.Value);
            }
            return sb.Length == 0 ? "(no calls yet)" : sb.ToString();
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

        // GetFinalPathNameByHandle returns a \\?\-prefixed path; tidy it for display
        // and for File.ReadAllBytes.
        private static string Clean(string path)
        {
            if (string.IsNullOrEmpty(path)) return "(unknown image)";
            path = path.TrimEnd('\0');
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) path = path.Substring(4);
            return path;
        }
    }
}
