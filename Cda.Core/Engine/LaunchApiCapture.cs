using System;
using System.Collections.Concurrent;
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
    ///     capturing calls IN to the app's own libraries from startup;
    ///   * <see cref="HookMode.Dialogs"/> splices only the OS dialog-box-creating
    ///     functions (see <see cref="DialogApiScanner"/>), so a startup nag/splash/
    ///     error dialog is attributed to the app function that raised it.
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
        public enum HookMode { Inline, Iat, Exports, Dialogs }

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
        /// (Dialogs mode) Raised when a dialog host that loads AFTER the first one is
        /// hooked (e.g. comctl32 after user32) is discovered — carrying its new dialog
        /// functions. The subscriber must install them with
        /// <see cref="CaptureSession.HookMore"/> on the poll thread (hook-list mutation
        /// isn't synchronized against the loop thread), so it can't be armed here.
        /// </summary>
        public event Action<IReadOnlyList<TracedFunction>>? MoreDialogsHooked;

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
        private bool _loaderBpSeen;   // the initial loader breakpoint has been consumed
        private bool _dialogHostSeen; // (Dialogs mode) a dialog-host LOAD_DLL (user32/comctl32/comdlg32/credui) has arrived post-loader-BP

        // (Dialogs mode) the live session, once the first dialog host is armed, and the
        // set of dialog entries already hooked — so a later host is hooked additively
        // (HookMore) and never double-hooked.
        private CaptureSession? _dialogSession;
        private readonly HashSet<ulong> _dialogHookedAddrs = new();
        private readonly List<ModuleInfo> _dialogModules = new();

        // --- hardware branch confirmation (dialogs mode) -------------------------------
        // Confirms which candidate branch a dialog's gate actually took, by arming the
        // candidates in hardware debug registers and reading the real EFLAGS on each #DB.
        // All of this runs on THIS loop thread; the UI enqueues requests via
        // RequestBranchProbe and receives results via BranchConfirmed.
        private const uint THREAD_ACCESS =
            NativeMethods.THREAD_GET_CONTEXT | NativeMethods.THREAD_SET_CONTEXT |
            NativeMethods.THREAD_SUSPEND_RESUME | NativeMethods.THREAD_QUERY_INFORMATION;

        private readonly DialogBranchConfirmer _confirmer = new();
        private readonly ConcurrentQueue<(ulong Key, ulong DialogApi, DialogBranchConfirmer.Candidate[] Candidates)> _probeRequests = new();
        private readonly Queue<(ulong Key, DialogBranchConfirmer.Candidate[] Candidates)> _drPending = new(); // PT-missed, awaiting a DR probe (loop thread only)
        private ulong[] _armedProbeAddrs = Array.Empty<ulong>(); // DR0..DR(n-1) contents (loop thread only)
        private ulong _armedProbeMask;                           // DR6 bits we own
        private ulong _armedCallSiteKey;                         // the call site currently probed
        private bool _targetIsWow64;                             // set once at first attach
        private IntelPt? _pt;                                    // Intel PT, if available (first-occurrence path)
        // PtDecoder now does full instruction-level control-flow reconstruction, so a TNT bit
        // is attributed to the exact branch that produced it (a non-executed candidate gets no
        // direction and can't be confirmed). Enabled for first-occurrence confirmation.
        private static readonly bool EnablePtFirstOccurrence = true;

        // Intel PT "read at the call" path (when PT is active). A poll-time trace read can miss
        // a flood-prone dialog (e.g. CreateWindowExW): by the time the UI drains the record and
        // reads the trace, window creation has overwritten the pre-call branch history in the
        // ring. So for a dialog PT couldn't confirm at poll time, we arm a hardware execute
        // breakpoint on the API entry; when the app next calls it, the whole process is frozen
        // at the entry with the buffer FRESH (the gate is the most-recent branch), and we read
        // the trace right there. `_drApiWatch` says the armed DRs are API entries, not branches.
        private sealed class ApiWatch
        {
            public ulong Key; public DialogBranchConfirmer.Candidate[] Cands = Array.Empty<DialogBranchConfirmer.Candidate>();
            public ulong AppLo, AppHi; public int Hits; public int AppTries;
            public readonly HashSet<ulong> Confirmed = new(); // reconstructed call sites already reported
        }
        private readonly Dictionary<ulong, ApiWatch> _apiWatch = new();  // API entry → pending fresh-read watch
        private readonly HashSet<ulong> _apiWatchDone = new();           // watches confirmed/given-up, to disarm
        private bool _drApiWatch;                                        // armed DRs are API entries (else branches)
        private bool _apiWatchDirty;                                     // watch set changed → re-arm needed
        // Give up on a watch after this many APP-ORIGINATED calls fail to yield the requested
        // gate (system-internal calls don't count — they're cheap return-address skips), with a
        // high total-hit backstop so a genuinely hot API entry can't trap the loop forever.
        private const int MaxAppWatchTries = 8;
        private const int MaxApiWatchHits = 2000;

        /// <summary>Raised (on the loop thread) when a dialog's gating branch is confirmed
        /// at runtime. The subscriber marshals it to the UI to upgrade the dialog row.</summary>
        public event Action<DialogBranchConfirmer.Confirmation>? BranchConfirmed;

        /// <summary>
        /// (Dialogs mode, UI/poll thread) Ask the loop to confirm which of <paramref name="candidates"/>
        /// the gate for <paramref name="callSiteKey"/> actually took. Non-blocking. The loop tries
        /// <b>Intel PT first</b> (always-on branch history — confirms this very occurrence by
        /// reading the trace and finding the branches before the call to
        /// <paramref name="dialogApiAddr"/>); if PT is unavailable or the call wrapped out of the
        /// ring, it falls back to arming DR0–DR3 (confirms on the caller's next run). Reports via
        /// <see cref="BranchConfirmed"/>.
        /// </summary>
        public void RequestGateConfirm(ulong callSiteKey, ulong dialogApiAddr, IReadOnlyList<DialogBranchConfirmer.Candidate> candidates)
        {
            if (candidates == null || candidates.Count == 0) return;
            var arr = new DialogBranchConfirmer.Candidate[candidates.Count];
            for (int i = 0; i < candidates.Count; i++) arr[i] = candidates[i];
            _probeRequests.Enqueue((callSiteKey, dialogApiAddr, arr));
        }

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

                // Dialog mode: begin Intel PT tracing from startup, so a dialog's gating branch
                // can be confirmed on its FIRST occurrence (else the DR path confirms on the next).
                // DISABLED: the current PtDecoder uses a scoped shortcut (the TNT bits right before
                // the dialog-call TIP = the gating branches) that is only correct when nothing else
                // branches between the gate and the call. On real/obfuscated targets that assumption
                // breaks and PT mis-attributes a TNT bit to a non-executed candidate → a FALSE
                // "[confirmed]". Until PtDecoder does full instruction-level control-flow
                // reconstruction (call stack + return compression, attributing each TNT bit to the
                // real branch address), we rely on the DR path, which only ever reports an executed
                // branch. The PT device/decoder stay for that future work.
                if (_mode == HookMode.Dialogs && EnablePtFirstOccurrence)
                {
                    try
                    {
                        var pt = IntelPt.TryCreate(out string? ptReason);
                        if (pt != null && pt.Start(_pid))
                        {
                            _pt = pt;
                            Log?.Invoke("Intel PT active — dialog gates are confirmed on their first occurrence.");
                            if (PtDiagVerbose)
                            {
                                try { if (PtDiagPath != null) File.WriteAllText(PtDiagPath, $"=== PT session · pid {_pid} ===\r\n"); } catch { }
                                _ptDiagStarted = true;
                                Log?.Invoke("Intel PT diagnostics → " + (PtDiagPath ?? "(file unavailable)"));
                            }
                        }
                        else
                        {
                            pt?.Dispose();
                            Log?.Invoke($"Intel PT unavailable ({ptReason ?? "start failed"}) — gates confirmed on the caller's next run (hardware breakpoints).");
                        }
                    }
                    catch (Exception ex) { Log?.Invoke("Intel PT setup error: " + ex.Message + " — using the hardware-breakpoint fallback."); }
                }

                while (true)
                {
                    if (!NativeMethods.WaitForDebugEvent(evt, 200))
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err == NativeMethods.ERROR_SEM_TIMEOUT)
                        {
                            if (_stop) { Detach(); break; }
                            ServiceProbeRequests(); // the target is idle — a good moment to (dis)arm
                            continue;
                        }
                        Log?.Invoke($"WaitForDebugEvent error {err}");
                        Detach();
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

                        case NativeMethods.CREATE_THREAD_DEBUG_EVENT:
                            // Arm a newly-created thread so a dialog raised on it is still
                            // confirmed. CREATE_THREAD_DEBUG_INFO.hThread is the first union
                            // field; the thread is frozen for this event (no suspend needed).
                            if (_armedProbeAddrs.Length > 0)
                                ArmProbeThread(Marshal.ReadIntPtr(evt, U), evtTid);
                            break;

                        case NativeMethods.LOAD_DLL_DEBUG_EVENT:
                        {
                            IntPtr hFile = Marshal.ReadIntPtr(evt, U);                   // LOAD_DLL_DEBUG_INFO.hFile
                            IntPtr baseOfDll = Marshal.ReadIntPtr(evt, U + IntPtr.Size); // .lpBaseOfDll
                            // Dialog capture: hook a dialog host (user32/comctl32/
                            // comdlg32/credui) the instant it maps — still frozen in this
                            // event, before the app can call into it — off the event's
                            // AUTHORITATIVE base (the debugger's module list can lag at a
                            // module's own load). This is how the LAZY hosts (comdlg32,
                            // credui, which load on first file/credential dialog rather than
                            // at startup) get armed; a host that loads later is added too.
                            if (_mode == HookMode.Dialogs && _loaderBpSeen)
                            {
                                try
                                {
                                    string fn = Path.GetFileName(ResolvePath(hFile));
                                    bool isHost = DialogApiScanner.IsDialogHostModule(fn);
                                    if (isHost)
                                    {
                                        _dialogHostSeen = true;
                                        ArmDialogs(NativeMethods.ToUInt64(baseOfDll), fn);
                                    }
                                    else if (!_hooked && _dialogHostSeen)
                                    {
                                        ArmDialogs(0, null); // safety retry before the first arm
                                    }
                                }
                                catch (Exception ex) { Log?.Invoke("dialog hook-on-load failed: " + ex.Message); }
                            }
                            CloseEventFile(hFile);
                            break;
                        }

                        case NativeMethods.EXCEPTION_DEBUG_EVENT:
                        {
                            uint exCode = (uint)Marshal.ReadInt32(evt, U); // EXCEPTION_RECORD.ExceptionCode

                            // A single-step #DB with one of OUR debug-register bits set is a
                            // branch-probe hit — evaluate it and consume the event. Any other
                            // single-step (or a non-ours DR6) falls through to the crash path.
                            // A 32-bit (WOW64) thread's #DB surfaces as STATUS_WX86_SINGLE_STEP.
                            if ((exCode == NativeMethods.EXCEPTION_SINGLE_STEP ||
                                 exCode == NativeMethods.STATUS_WX86_SINGLE_STEP) && HandleProbeHit(evtTid))
                            {
                                cont = NativeMethods.DBG_CONTINUE;
                                break;
                            }

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
                                    if (_mode == HookMode.Dialogs)
                                    {
                                        // Dialog capture: the host DLLs may not be mapped
                                        // yet — the common dialogs (comdlg32) and credential
                                        // prompts (credui) load on first use, and user32/
                                        // comctl32 can be absent in a .NET/packed target. Arm
                                        // any already loaded; if none, DON'T abort — the
                                        // LOAD_DLL handler arms them the instant they map.
                                        try { ArmDialogs(0, null); }
                                        catch (Exception ex) { Log?.Invoke("startup dialog hook failed: " + ex.Message); }
                                        if (!_hooked)
                                            Log?.Invoke("dialog hosts (user32/comctl32/comdlg32/credui) aren't loaded yet — " +
                                                        "watching, and arming the moment they load…");
                                    }
                                    else
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
                            try { _pt?.Dispose(); _pt = null; } catch { }
                            Log?.Invoke("target exited.");
                            TargetExited?.Invoke();
                            return;
                    }

                    NativeMethods.ContinueDebugEvent(evtPid, evtTid, cont);

                    ServiceProbeRequests(); // pick up any UI-requested branch probe
                    if (_stop) { Detach(); break; }
                }
            }
            catch (Exception ex)
            {
                Log?.Invoke("API launch loop error: " + ex.Message);
                // Clear any armed debug registers so the target doesn't fault on the next
                // candidate execution after we're gone (they survive a lost debugger).
                try { if (_armedProbeAddrs.Length > 0) DisarmProbeAllThreads(); } catch { }
                try { _pt?.Dispose(); _pt = null; } catch { }
            }
            finally
            {
                Marshal.FreeHGlobal(evt);
            }
        }

        private void Detach()
        {
            // The debug registers we set are part of each thread's context and are NOT
            // cleared by detaching — leave them armed and the next candidate hit raises an
            // unhandled #DB in the target. Clear them on every thread first.
            try { if (_armedProbeAddrs.Length > 0) DisarmProbeAllThreads(); } catch { /* best effort */ }
            try { _pt?.Dispose(); _pt = null; } catch { /* best effort — stops PT tracing */ }
            try { NativeMethods.DebugActiveProcessStop((uint)_pid); } catch { /* best effort */ }
            Log?.Invoke("detached from target (left running).");
        }

        // --- hardware branch probe (arm / disarm / service / hit) ----------------------

        // Service the UI's branch-probe queue. Called on the loop thread only. Intel PT and
        // the DR fallback are DECOUPLED: PT is stateless (reads the trace on demand, no
        // per-site limit) so every request is tried against PT immediately — a pending DR
        // probe must NOT starve PT confirmations, whose trace data ages quickly. Only the
        // PT-misses are gated by the DR "one call site (≤4 DRs) at a time" rule.
        private void ServiceProbeRequests()
        {
            // 1. Intel PT first, for EVERY new request. Confirms this occurrence retroactively;
            //    on a miss, watch the API entry to read the trace FRESH at its next call (PT
            //    active) or queue a DR branch-probe (no PT — confirms on the caller's next run).
            while (_probeRequests.TryDequeue(out var req))
            {
                if (_pt != null)
                {
                    if (!TryPtConfirm(req.Key, req.DialogApi, req.Candidates))
                        RequestApiWatch(req.DialogApi, req.Key, req.Candidates);
                    continue;
                }
                _drPending.Enqueue((req.Key, req.Candidates));
            }

            // 2a. PT active: (re)arm the API-entry watches for fresh reads (see ServiceApiWatch).
            if (_pt != null) { ServiceApiWatch(); return; }

            // 2b. DR fallback: free the current probe once its nearest gate has routed in (or
            //    give-up) — NOT on any confirmation, or we'd disarm mid-pass on a farther branch.
            if (_armedProbeAddrs.Length > 0)
            {
                if (!_confirmer.IsResolved(_armedCallSiteKey)) return;
                DisarmProbeAllThreads();
                _armedProbeAddrs = Array.Empty<ulong>();
                _armedProbeMask = 0;
            }

            // 3. Arm the next PT-missed call site (confirms on the caller's next run).
            while (_drPending.Count > 0)
            {
                var d = _drPending.Dequeue();
                var arm = _confirmer.Register(d.Key, d.Candidates);
                if (arm.Count == 0) continue; // already confirmed, or nothing armable
                var addrs = new ulong[arm.Count];
                for (int i = 0; i < arm.Count; i++) addrs[i] = arm[i];
                _armedProbeAddrs = addrs;
                _armedProbeMask = (1UL << addrs.Length) - 1;
                _armedCallSiteKey = d.Key;
                ArmProbeAllThreads();
                break;
            }
        }

        // Register a dialog API entry to watch for a FRESH trace read at its next call. Bounded
        // to 4 (the hardware DR count); the app rarely raises dialogs through more than a couple
        // of distinct APIs, and the poll-time read still covers the rest.
        private void RequestApiWatch(ulong apiAddr, ulong key, DialogBranchConfirmer.Candidate[] cands)
        {
            if (apiAddr == 0 || _apiWatch.ContainsKey(apiAddr) || _apiWatch.Count >= 4 || cands.Length == 0) return;
            ulong lo = ulong.MaxValue, hi = 0;
            foreach (var c in cands) { if (c.Address < lo) lo = c.Address; if (c.Address > hi) hi = c.Address; }
            _apiWatch[apiAddr] = new ApiWatch
            {
                Key = key, Cands = cands,
                AppLo = lo > 0x10000000 ? lo - 0x10000000 : 0, AppHi = hi + 0x10000000,
            };
            _apiWatchDirty = true;
            PtDiag($"watch armed on API 0x{apiAddr:X} (fresh read at next call); {_apiWatch.Count} watched");
        }

        // (Re)arm the set of watched API entries in the debug registers, dropping any that have
        // confirmed or given up. Only touches the threads when the set actually changed.
        private void ServiceApiWatch()
        {
            if (_apiWatchDone.Count > 0)
            {
                foreach (var a in _apiWatchDone) _apiWatch.Remove(a);
                _apiWatchDone.Clear();
                _apiWatchDirty = true;
            }
            if (!_apiWatchDirty) return;
            _apiWatchDirty = false;

            var addrs = new ulong[Math.Min(4, _apiWatch.Count)];
            int i = 0; foreach (var a in _apiWatch.Keys) { if (i >= addrs.Length) break; addrs[i++] = a; }
            _armedProbeAddrs = addrs;
            _armedProbeMask = addrs.Length == 0 ? 0 : (1UL << addrs.Length) - 1;
            _drApiWatch = true;
            if (addrs.Length > 0) ArmProbeAllThreads(); else DisarmProbeAllThreads();
        }

        // An API-entry watch fired: the whole process is frozen at the dialog API's first
        // instruction, so the trace ring holds the pre-call branch history intact. Read it
        // fresh and reconstruct the gate. Only app-originated calls (return address in the
        // candidates' module neighbourhood) are worth the read; system-internal calls are
        // stepped over cheaply. Returns having marked confirmed/exhausted watches for disarm.
        private void HandleApiWatchHit(IThreadContext ctx, ulong hit)
        {
            int psize = _targetIsWow64 ? 4 : 8;
            var word = new byte[8];
            for (int i = 0; i < _armedProbeAddrs.Length; i++)
            {
                if ((hit & (1UL << i)) == 0) continue;
                ulong apiAddr = _armedProbeAddrs[i];
                if (!_apiWatch.TryGetValue(apiAddr, out var w)) continue;

                w.Hits++;
                // Only an app-originated call is worth a (large) trace read + reconstruct: check
                // the return address at [RSP]. A failed/short read leaves ret=0, which must NOT
                // count as app code even when AppLo==0 (a 32-bit target's low module base).
                ulong ret = 0;
                bool readOk = _pt != null && _pt.ReadMemory(ctx.StackPointer, word) >= psize;
                if (readOk) ret = psize == 8 ? BitConverter.ToUInt64(word, 0) : BitConverter.ToUInt32(word, 0);
                bool appCall = readOk && ret != 0 && ret >= w.AppLo && ret <= w.AppHi;

                if (appCall)
                {
                    w.AppTries++;
                    byte[]? trace = null;
                    try { trace = _pt?.ReadTrace(); } catch { }
                    if (trace != null)
                    {
                        DialogBranchConfirmer.Confirmation? conf = null;
                        // keyByCallSite: report the branch for the call site that actually fired,
                        // not necessarily the one whose request armed this watch.
                        try { conf = PtDecoder.TryConfirm(trace, apiAddr, w.Key, w.Cands, !_targetIsWow64, (a, b) => _pt!.ReadMemory(a, b), PtDiagSink, keyByCallSite: true); }
                        catch (Exception ex) { PtDiag("fresh-read decode error: " + ex.Message); }
                        if (conf != null && w.Confirmed.Add(conf.CallSiteKey))
                        {
                            PtDiag($"FRESH-READ confirmed (ret=0x{ret:X}): {conf.Text}");
                            BranchConfirmed?.Invoke(conf);
                            // Done once the site that requested the watch is confirmed; other
                            // sites sharing this API entry are upgraded as a bonus meanwhile.
                            if (conf.CallSiteKey == w.Key) _apiWatchDone.Add(apiAddr);
                        }
                    }
                }
                if (!_apiWatchDone.Contains(apiAddr) && (w.AppTries >= MaxAppWatchTries || w.Hits >= MaxApiWatchHits))
                {
                    PtDiag($"watch on API 0x{apiAddr:X} gave up (appTries={w.AppTries} hits={w.Hits})");
                    _apiWatchDone.Add(apiAddr);
                }
            }
        }

        // PT diagnostics are OFF by default (the feature is validated). Set CDA_PT_DIAG=1 to
        // turn on the verbose per-thread/per-reconstruction trace when diagnosing a new target;
        // it then goes to BOTH the Diag pane AND a file next to the exe (the pane can scroll/
        // truncate; the file is the reliable copy).
        public static readonly bool PtDiagVerbose = Environment.GetEnvironmentVariable("CDA_PT_DIAG") == "1";
        public static readonly string? PtDiagPath = PtDiagVerbose ? ComputePtDiagPath() : null;
        private static string? ComputePtDiagPath()
        {
            foreach (var dir in new[] { AppContext.BaseDirectory,
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Cda.Modern") })
            {
                try { Directory.CreateDirectory(dir); var p = Path.Combine(dir, "cda-pt-diag.log"); File.AppendAllText(p, ""); return p; }
                catch { /* try next */ }
            }
            return null;
        }
        // Null when quiet, so it's cheap to pass as PtDecoder's optional diagnostic sink.
        private Action<string>? PtDiagSink => PtDiagVerbose ? PtDiag : null;
        private static bool _ptDiagStarted;
        private void PtDiag(string m)
        {
            if (!PtDiagVerbose) return;
            Log?.Invoke("[PT] " + m);
            try
            {
                if (PtDiagPath == null) return;
                if (!_ptDiagStarted) { try { if (new FileInfo(PtDiagPath).Length > 512 * 1024) File.WriteAllText(PtDiagPath, ""); } catch { } _ptDiagStarted = true; }
                File.AppendAllText(PtDiagPath, m + Environment.NewLine);
            }
            catch { /* diagnostics must never throw */ }
        }

        // Read the Intel PT trace and decode the gate for this dialog call. Returns true (and
        // raises BranchConfirmed) on success; false if PT can't confirm (unavailable, the call
        // wrapped out of the ring, or a decode miss) so the caller uses the DR fallback.
        private bool TryPtConfirm(ulong key, ulong dialogApiAddr, DialogBranchConfirmer.Candidate[] candidates)
        {
            if (_pt == null || dialogApiAddr == 0) { PtDiag($"skip: pt={( _pt != null)} api=0x{dialogApiAddr:X}"); return false; }
            byte[]? trace;
            try { trace = _pt.ReadTrace(); } catch (Exception ex) { PtDiag("ReadTrace threw: " + ex.Message); return false; }
            if (trace == null) { PtDiag("ReadTrace returned null (no trace data)"); return false; }
            DialogBranchConfirmer.Confirmation? conf;
            try { conf = PtDecoder.TryConfirm(trace, dialogApiAddr, key, candidates, !_targetIsWow64, (addr, buf) => _pt!.ReadMemory(addr, buf), PtDiagSink); }
            catch (Exception ex) { PtDiag("decode error: " + ex.Message); return false; }
            if (conf == null) return false;
            BranchConfirmed?.Invoke(conf);
            return true;
        }

        // A single-step #DB fired on thread tid. If it's one of our branch-probe DRs,
        // evaluate the branch's real direction from EFLAGS, report any confirmation, step
        // over the breakpoint (resume flag) so it stays armed, and return true. If DR6 has
        // none of our bits, return false so the crash path handles it.
        private bool HandleProbeHit(uint tid)
        {
            if (_armedProbeAddrs.Length == 0) return false;
            IntPtr h = NativeMethods.OpenThread(THREAD_ACCESS, false, tid);
            if (h == IntPtr.Zero) return false;
            try
            {
                using var ctx = ThreadContext.Capture(h, _targetIsWow64);
                if (ctx == null) return false;

                ulong hit = ctx.Dr6 & _armedProbeMask;
                if (hit == 0) return false; // not one of ours

                if (_drApiWatch)
                {
                    // Armed DRs are dialog API entries: read the trace fresh at the call.
                    HandleApiWatchHit(ctx, hit);
                }
                else
                {
                    // Armed DRs are candidate branches: evaluate each from EFLAGS.
                    for (int i = 0; i < _armedProbeAddrs.Length; i++)
                    {
                        if ((hit & (1UL << i)) == 0) continue;
                        var conf = _confirmer.OnBreakpointHit(_armedCallSiteKey, i, ctx);
                        if (conf != null) BranchConfirmed?.Invoke(conf);
                    }
                }

                ctx.Dr6 = 0;                              // acknowledge
                ctx.EFlags |= ThreadContext.ResumeFlag;   // step over the instruction once
                ctx.Apply(h);
                return true;
            }
            finally { NativeMethods.CloseHandle(h); }
        }

        // Arm the current probe addresses on every existing thread. The target is live here
        // (between debug events), so each thread is briefly suspended for the context swap.
        private void ArmProbeAllThreads()
        {
            ForEachThread(h =>
            {
                NativeMethods.SuspendThread(h);
                try
                {
                    using var ctx = ThreadContext.Capture(h, _targetIsWow64);
                    if (ctx == null) return false;
                    ctx.SetBreakpoints(_armedProbeAddrs);
                    return ctx.Apply(h);
                }
                finally { NativeMethods.ResumeThread(h); }
            });
        }

        private void DisarmProbeAllThreads()
        {
            ForEachThread(h =>
            {
                NativeMethods.SuspendThread(h);
                try
                {
                    using var ctx = ThreadContext.Capture(h, _targetIsWow64);
                    if (ctx == null) return false;
                    ctx.ClearBreakpoints();
                    return ctx.Apply(h);
                }
                finally { NativeMethods.ResumeThread(h); }
            });
        }

        // Arm a single thread from a CREATE_THREAD event (frozen — no suspend), by the
        // system-owned handle when present, else by tid.
        private void ArmProbeThread(IntPtr hThread, uint tid)
        {
            if (hThread != IntPtr.Zero && hThread != NativeMethods.INVALID_HANDLE_VALUE)
            {
                using var ctx = ThreadContext.Capture(hThread, _targetIsWow64);
                if (ctx != null) { ctx.SetBreakpoints(_armedProbeAddrs); ctx.Apply(hThread); }
                return;
            }
            IntPtr h = NativeMethods.OpenThread(THREAD_ACCESS, false, tid);
            if (h == IntPtr.Zero) return;
            try
            {
                using var ctx = ThreadContext.Capture(h, _targetIsWow64);
                if (ctx != null) { ctx.SetBreakpoints(_armedProbeAddrs); ctx.Apply(h); }
            }
            finally { NativeMethods.CloseHandle(h); }
        }

        // Enumerate the target's threads and run an action on a handle to each.
        private int ForEachThread(Func<IntPtr, bool> action)
        {
            IntPtr snap = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPTHREAD, 0);
            if (snap == NativeMethods.INVALID_HANDLE_VALUE) return 0;
            int count = 0;
            try
            {
                var te = new NativeMethods.THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<NativeMethods.THREADENTRY32>() };
                if (!NativeMethods.Thread32First(snap, ref te)) return 0;
                do
                {
                    if (te.th32OwnerProcessID != (uint)_pid) continue;
                    IntPtr h = NativeMethods.OpenThread(THREAD_ACCESS, false, te.th32ThreadID);
                    if (h == IntPtr.Zero) continue;
                    try { if (action(h)) count++; }
                    catch { /* one bad thread shouldn't abort the sweep */ }
                    finally { NativeMethods.CloseHandle(h); }
                }
                while (NativeMethods.Thread32Next(snap, ref te));
            }
            finally { NativeMethods.CloseHandle(snap); }
            return count;
        }

        private static void CloseEventFile(IntPtr h)
        {
            if (h != IntPtr.Zero && h != NativeMethods.INVALID_HANDLE_VALUE)
                NativeMethods.CloseHandle(h);
        }

        // The on-disk path behind a LOAD_DLL event's file handle, to recognize which
        // module just mapped (used to spot a dialog host for dialog capture).
        private static string ResolvePath(IntPtr hFile)
        {
            if (hFile == IntPtr.Zero || hFile == NativeMethods.INVALID_HANDLE_VALUE) return "";
            char[] buf = new char[600];
            uint n = NativeMethods.GetFinalPathNameByHandleW(hFile, buf, (uint)buf.Length, 0);
            if (n == 0 || n >= buf.Length) return "";
            return new string(buf, 0, (int)n);
        }

        // (Dialogs mode) Discover and hook the dialog-box functions currently mapped,
        // optionally forcing a just-loaded module (from a LOAD_DLL event's authoritative
        // base) into the scan so a lag in the debugger's module list at the module's own
        // load event can't hide it. The FIRST host creates the session and raises
        // <see cref="Hooked"/> here on the loop thread — safe because no poll runs yet.
        // A LATER host (e.g. comctl32 after user32) is handed to the UI via
        // <see cref="MoreDialogsHooked"/>, which installs it with HookMore on the poll
        // thread (hook-list mutation isn't synchronized against the loop thread).
        private void ArmDialogs(ulong ensureBase, string? ensureName)
        {
            ModuleMap map;
            DialogApiScanner.Result dlg;
            bool is64;
            using (var probe = TargetProcess.Attach(_pid, forWrite: false))
            {
                is64 = probe.Is64Bit;
                _targetIsWow64 = !is64; // a 32-bit target needs the WOW64 context path (phase B)
                var mods = new List<ModuleInfo>(probe.EnumerateModules());
                if (ensureBase != 0 && ensureName != null &&
                    !mods.Exists(m => m.BaseAddress == ensureBase))
                {
                    uint size = ReadSizeOfImage(probe, ensureBase);
                    if (size > 0) mods.Add(new ModuleInfo(ensureName, ensureBase, size, ensureName));
                }
                map = new ModuleMap(mods);
                dlg = DialogApiScanner.Discover(probe, map);
            }

            var fresh = new List<TracedFunction>();
            foreach (var f in dlg.Functions)
                if (!_dialogHookedAddrs.Contains(f.Address)) fresh.Add(f);
            if (fresh.Count == 0) return;

            var addrs = new List<ulong>(fresh.Count);
            foreach (var f in fresh) addrs.Add(f.Address);

            if (_dialogSession == null)
            {
                // First host: safe to hook here — the UI hasn't started polling yet.
                var session = CaptureSession.Start(_pid, addrs, _maxFunctions, _bufferRecords,
                    out int instrumented, out int skipped, out string? firstError);
                if (instrumented <= 0)
                {
                    session.Dispose();
                    Log?.Invoke($"found {fresh.Count} dialog API(s) but none could be hooked ({firstError ?? "?"}); will retry.");
                    return;
                }
                _dialogSession = session;
                foreach (var f in fresh) _dialogHookedAddrs.Add(f.Address);
                foreach (var m in dlg.Modules)
                    if (!_dialogModules.Exists(x => x.BaseAddress == m.BaseAddress)) _dialogModules.Add(m);

                var ds = new TraceDataset { TimeStart = 0, TimeEnd = 1 };
                ds.Modules.AddRange(_dialogModules);
                ds.Functions.AddRange(fresh);
                ds.PruneUnreferencedModules();

                _hooked = true;
                Log?.Invoke($"dialog capture: hooked {instrumented} dialog function(s) — a dialog from here on " +
                            "is attributed to the app function that raised it.");
                Hooked?.Invoke(new HookedApis
                {
                    Pid = _pid, Is64Bit = is64, Mode = _mode, Session = session, Dataset = ds,
                    ModuleMap = map, Instrumented = instrumented, Skipped = skipped, FirstError = firstError,
                    DistinctApis = fresh.Count, ApiModules = dlg.Modules.Count,
                });
            }
            else
            {
                // A later host: mark hooked and let the UI install them (HookMore must
                // run on the poll thread). Marking now prevents re-raising on retries.
                foreach (var f in fresh) _dialogHookedAddrs.Add(f.Address);
                Log?.Invoke($"dialog capture: {fresh.Count} more dialog function(s) available (from " +
                            $"{ensureName ?? "a newly-loaded module"}) — installing…");
                MoreDialogsHooked?.Invoke(fresh);
            }
        }

        // Read SizeOfImage from a mapped module's PE header at the given base. Lets a
        // module just delivered by a LOAD_DLL event be scanned off its authoritative
        // base even when the debugger's module list hasn't caught up. 0 on any problem.
        private static uint ReadSizeOfImage(TargetProcess process, ulong baseAddr)
        {
            byte[] hdr = new byte[0x400];
            if (process.ReadMemory(baseAddr, hdr) < hdr.Length) return 0;
            if (hdr[0] != (byte)'M' || hdr[1] != (byte)'Z') return 0;
            int e = BitConverter.ToInt32(hdr, 0x3C);
            if (e <= 0 || e + 24 + 60 > hdr.Length) return 0;
            if (hdr[e] != (byte)'P' || hdr[e + 1] != (byte)'E') return 0;
            return BitConverter.ToUInt32(hdr, e + 24 + 56); // OptionalHeader.SizeOfImage
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
            // Dialogs mode is armed by ArmDialogs (which handles late-loaded user32/
            // comctl32), not through here.
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
