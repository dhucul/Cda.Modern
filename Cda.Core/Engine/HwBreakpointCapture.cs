using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using Cda.Core.Model;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Captures calls to a handful of functions using the CPU's hardware debug
    /// registers — writing NOTHING to the target's memory. Where an inline hook
    /// splices the function entry (visible to a code checksum) and an IAT hook
    /// rewrites an import pointer (data), this sets DR0–DR3 on every thread to the
    /// function entry addresses and catches the resulting #DB exceptions in a
    /// debugger loop. The target's code and data are byte-for-byte untouched, so an
    /// anti-tamper binary that self-terminates when patched is captured cleanly.
    ///
    /// The trade-offs are inherent to the mechanism:
    ///   • at most FOUR addresses at once (there are four debug-address registers);
    ///   • it must attach as a debugger (DebugActiveProcess), so a target that also
    ///     anti-DEBUGS may notice the attach — unlike the IAT path, which needs no
    ///     debugger;
    ///   • x64 only (a WOW64 thread needs a separate 32-bit context path).
    ///
    /// On each hit the call is reconstructed entirely host-side from the thread
    /// context: RIP is the callee entry, [RSP] is the caller's return address, and
    /// RCX/RDX/R8/R9 are the first four integer arguments. The breakpoint is then
    /// stepped over using the EFLAGS resume flag so it stays armed without looping.
    /// Records are delivered in batches through <see cref="RecordsCaptured"/>, the
    /// same shape the other capture paths emit, so the views consume them
    /// unchanged.
    /// </summary>
    public sealed class HwBreakpointCapture : IDisposable
    {
        /// <summary>A batch of newly captured calls (already host-side decoded).</summary>
        public event Action<List<CallRecord>>? RecordsCaptured;

        /// <summary>Human-readable progress/diagnostics.</summary>
        public event Action<string>? Log;

        /// <summary>The target exited (or we detached); the UI should stop.</summary>
        public event Action? TargetExited;

        private const uint THREAD_ACCESS =
            NativeMethods.THREAD_GET_CONTEXT | NativeMethods.THREAD_SET_CONTEXT |
            NativeMethods.THREAD_SUSPEND_RESUME | NativeMethods.THREAD_QUERY_INFORMATION;

        private readonly int _pid;
        private readonly ulong[] _addrs;       // up to 4 watched function entries
        private readonly ulong _ourMask;       // DR6 bits we own (bits 0..n-1)
        private readonly int _snapshotWords;

        private Thread? _thread;
        private volatile bool _stop;
        private TargetProcess? _reader;        // read-only handle for stack/return reads
        private bool _firstHit;

        private readonly long _t0 = Stopwatch.GetTimestamp();
        private static readonly double TicksPerSecond = Stopwatch.Frequency;

        public HwBreakpointCapture(int pid, IReadOnlyList<ulong> addresses, int snapshotWords = 24)
        {
            _pid = pid;
            var list = new List<ulong>();
            foreach (var a in addresses)
                if (a != 0 && !list.Contains(a) && list.Count < 4) list.Add(a);
            _addrs = list.ToArray();
            _ourMask = _addrs.Length >= 4 ? 0xFUL : (1UL << _addrs.Length) - 1;
            _snapshotWords = Math.Max(0, snapshotWords);
        }

        /// <summary>How many addresses are actually being watched (1–4).</summary>
        public int BreakpointCount => _addrs.Length;

        public void Start()
        {
            _thread = new Thread(Run) { IsBackground = true, Name = "CDA hwbp loop" };
            _thread.Start();
        }

        public void Stop() => _stop = true;
        public void Dispose() => Stop();

        /// <summary>
        /// Block until the debug loop has exited (and so has cleared the debug
        /// registers and detached), up to <paramref name="ms"/>. Call this on app
        /// shutdown so the target isn't left with armed breakpoints after the
        /// debugger is gone (which would fault it on the next hit).
        /// </summary>
        public bool WaitForExit(int ms) => _thread == null || _thread.Join(ms);

        // The whole debugger lifecycle runs on this one thread: DebugActiveProcess,
        // every WaitForDebugEvent/ContinueDebugEvent, and the detach must all be
        // issued by the same thread that attached.
        private void Run()
        {
            if (_addrs.Length == 0)
            {
                Log?.Invoke("hardware bp: no function addresses to watch.");
                TargetExited?.Invoke();
                return;
            }

            try { _reader = TargetProcess.Attach(_pid, forWrite: false); }
            catch (Exception ex) { Log?.Invoke("hardware bp: couldn't open target for reading (" + ex.Message + ") — args will still be captured, callers may be blank."); }

            if (!NativeMethods.DebugActiveProcess((uint)_pid))
            {
                int err = Marshal.GetLastWin32Error();
                Log?.Invoke($"hardware bp: DebugActiveProcess failed (error {err}). The target may be protected, " +
                            "already being debugged, or running at higher integrity — try launching CDA as administrator.");
                _reader?.Dispose(); _reader = null;
                TargetExited?.Invoke();
                return;
            }
            // Detaching (or this process dying) must NOT kill the target.
            NativeMethods.DebugSetProcessKillOnExit(false);
            Log?.Invoke($"hardware bp: attached to pid {_pid}; arming {_addrs.Length} address(es) on every thread (DR0–DR{_addrs.Length - 1}).");

            IntPtr evt = Marshal.AllocHGlobal(4096);
            int U = IntPtr.Size == 8 ? 16 : 12; // offset of the event-specific union in DEBUG_EVENT
            var pending = new List<CallRecord>();
            long lastFlush = Environment.TickCount64;

            try
            {
                while (true)
                {
                    if (!NativeMethods.WaitForDebugEvent(evt, 100))
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err == NativeMethods.ERROR_SEM_TIMEOUT)
                        {
                            FlushIfDue(pending, ref lastFlush);
                            if (_stop) break;
                            continue;
                        }
                        Log?.Invoke($"hardware bp: WaitForDebugEvent error {err} — stopping.");
                        break;
                    }

                    uint code = (uint)Marshal.ReadInt32(evt, 0);
                    uint evtPid = (uint)Marshal.ReadInt32(evt, 4);
                    uint evtTid = (uint)Marshal.ReadInt32(evt, 8);
                    uint cont = NativeMethods.DBG_CONTINUE;

                    switch (code)
                    {
                        case NativeMethods.CREATE_PROCESS_DEBUG_EVENT:
                            // We own the file handle in CREATE_PROCESS_DEBUG_INFO.hFile
                            // (union+0) and must close it; the process/thread handles
                            // are the system's. Arm every existing thread now (the
                            // process is frozen for this event).
                            CloseHandleSafe(Marshal.ReadIntPtr(evt, U));
                            ArmAllThreads();
                            break;

                        case NativeMethods.CREATE_THREAD_DEBUG_EVENT:
                            // CREATE_THREAD_DEBUG_INFO.hThread is the first union field.
                            // Covers both threads that existed at attach (the system
                            // synthesizes a create event for each) and new ones.
                            ArmThread(Marshal.ReadIntPtr(evt, U), evtTid);
                            break;

                        case NativeMethods.EXCEPTION_DEBUG_EVENT:
                        {
                            uint exCode = (uint)Marshal.ReadInt32(evt, U); // EXCEPTION_RECORD.ExceptionCode
                            if (exCode == NativeMethods.EXCEPTION_SINGLE_STEP && HandleHwBreak(evtTid, pending))
                                cont = NativeMethods.DBG_CONTINUE;          // one of ours — consumed
                            else if (exCode == NativeMethods.EXCEPTION_BREAKPOINT || exCode == NativeMethods.STATUS_WX86_BREAKPOINT)
                                cont = NativeMethods.DBG_CONTINUE;          // initial attach breakpoint
                            else
                                cont = NativeMethods.DBG_EXCEPTION_NOT_HANDLED; // not ours — hand back to the app
                            break;
                        }

                        case NativeMethods.EXIT_PROCESS_DEBUG_EVENT:
                            NativeMethods.ContinueDebugEvent(evtPid, evtTid, NativeMethods.DBG_CONTINUE);
                            Flush(pending);
                            Log?.Invoke("hardware bp: target exited.");
                            TargetExited?.Invoke();
                            return;
                    }

                    NativeMethods.ContinueDebugEvent(evtPid, evtTid, cont);
                    FlushIfDue(pending, ref lastFlush);
                    if (_stop) break;
                }

                // Clean detach: the debug registers we set are part of each thread's
                // context and are NOT cleared by detaching — if we left them armed,
                // the next hit would raise an unhandled #DB and crash the target. So
                // clear them on every thread before DebugActiveProcessStop.
                DisarmAllThreads();
                NativeMethods.DebugActiveProcessStop((uint)_pid);
                Flush(pending);
                Log?.Invoke("hardware bp: detached (debug registers cleared).");
            }
            catch (Exception ex)
            {
                Log?.Invoke("hardware bp loop error: " + ex.Message);
                try { DisarmAllThreads(); } catch { }
                try { NativeMethods.DebugActiveProcessStop((uint)_pid); } catch { }
            }
            finally
            {
                Marshal.FreeHGlobal(evt);
                _reader?.Dispose(); _reader = null;
            }
        }

        // --- arming / disarming ----------------------------------------------

        // Set our breakpoints on every thread of the target. Called for the
        // initial attach (process frozen) and so covers all existing threads.
        private void ArmAllThreads()
        {
            int armed = ForEachThread(h =>
            {
                using var ctx = ThreadContextX64.Capture(h);
                if (ctx == null) return false;
                ctx.SetBreakpoints(_addrs);
                return ctx.Apply(h);
            });
            Log?.Invoke($"hardware bp: armed {armed} existing thread(s).");
        }

        // Arm a single thread by the handle from a CREATE_THREAD event (owned by the
        // system — we don't close it), falling back to opening by tid.
        private void ArmThread(IntPtr hThread, uint tid)
        {
            if (hThread != IntPtr.Zero && hThread != NativeMethods.INVALID_HANDLE_VALUE)
            {
                using var ctx = ThreadContextX64.Capture(hThread);
                if (ctx != null) { ctx.SetBreakpoints(_addrs); ctx.Apply(hThread); }
                return;
            }
            IntPtr h = NativeMethods.OpenThread(THREAD_ACCESS, false, tid);
            if (h == IntPtr.Zero) return;
            try
            {
                using var ctx = ThreadContextX64.Capture(h);
                if (ctx != null) { ctx.SetBreakpoints(_addrs); ctx.Apply(h); }
            }
            finally { NativeMethods.CloseHandle(h); }
        }

        // Clear our breakpoints on every thread. Runs on stop, when the target's
        // threads are live, so each is briefly suspended for the context swap.
        private void DisarmAllThreads()
        {
            ForEachThread(h =>
            {
                NativeMethods.SuspendThread(h);
                try
                {
                    using var ctx = ThreadContextX64.Capture(h);
                    if (ctx == null) return false;
                    ctx.ClearBreakpoints();
                    return ctx.Apply(h);
                }
                finally { NativeMethods.ResumeThread(h); }
            });
        }

        // Enumerate the target's threads and run an action on a handle to each;
        // returns how many the action reported success for.
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

        // --- the hit handler --------------------------------------------------

        // A #DB fired on thread tid. If it's one of our hardware breakpoints,
        // record the call, clear the status, and set the resume flag so the thread
        // steps over the entry without re-triggering. Returns true iff it was ours.
        private bool HandleHwBreak(uint tid, List<CallRecord> pending)
        {
            IntPtr h = NativeMethods.OpenThread(THREAD_ACCESS, false, tid);
            if (h == IntPtr.Zero) return false;
            try
            {
                using var ctx = ThreadContextX64.Capture(h);
                if (ctx == null) return false;

                // DR6 bits 0–3 say which DR0–DR3 matched; is any of ours set?
                if ((ctx.Dr6 & _ourMask) == 0) return false;

                pending.Add(BuildRecord(ctx));
                if (!_firstHit) { _firstHit = true; Log?.Invoke("hardware bp: first hit recorded — capturing."); }

                ctx.Dr6 = 0;                          // acknowledge
                ctx.EFlags |= ThreadContextX64.ResumeFlag; // step over the entry once
                ctx.Apply(h);
                return true;
            }
            finally { NativeMethods.CloseHandle(h); }
        }

        private CallRecord BuildRecord(ThreadContextX64 ctx)
        {
            ulong rsp = ctx.Rsp;
            ulong source = ReadPtr(rsp); // the return address the CALL pushed
            var args = new[] { ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9 };
            var snapshot = ReadSnapshot(rsp, _snapshotWords);
            double time = (double)(Stopwatch.GetTimestamp() - _t0) / TicksPerSecond;
            return new CallRecord
            {
                Time = time,
                Source = source,
                Destination = ctx.Rip, // execute breakpoint faults AT the entry
                StackPointer = rsp,
                IntegerArgs = args,
                StackSnapshot = snapshot,
            };
        }

        private ulong ReadPtr(ulong addr)
        {
            if (_reader == null || addr == 0) return 0;
            Span<byte> b = stackalloc byte[8];
            try { if (_reader.ReadMemory(addr, b) < 8) return 0; }
            catch { return 0; }
            return BinaryPrimitives.ReadUInt64LittleEndian(b);
        }

        private ulong[] ReadSnapshot(ulong rsp, int words)
        {
            if (_reader == null || words <= 0 || rsp == 0) return Array.Empty<ulong>();
            byte[] buf = new byte[words * 8];
            int n;
            try { n = _reader.ReadMemory(rsp, buf); } catch { return Array.Empty<ulong>(); }
            if (n < 8) return Array.Empty<ulong>();
            int got = n / 8;
            var snap = new ulong[got];
            for (int i = 0; i < got; i++)
                snap[i] = BinaryPrimitives.ReadUInt64LittleEndian(buf.AsSpan(i * 8));
            return snap;
        }

        // --- batching ---------------------------------------------------------

        private void FlushIfDue(List<CallRecord> pending, ref long lastFlush)
        {
            long now = Environment.TickCount64;
            if (pending.Count == 0) { lastFlush = now; return; }
            if (pending.Count >= 64 || now - lastFlush >= 100)
            {
                Flush(pending);
                lastFlush = now;
            }
        }

        private void Flush(List<CallRecord> pending)
        {
            if (pending.Count == 0) return;
            var batch = new List<CallRecord>(pending);
            pending.Clear();
            RecordsCaptured?.Invoke(batch);
        }

        private static void CloseHandleSafe(IntPtr h)
        {
            if (h != IntPtr.Zero && h != NativeMethods.INVALID_HANDLE_VALUE)
                try { NativeMethods.CloseHandle(h); } catch { }
        }
    }
}
