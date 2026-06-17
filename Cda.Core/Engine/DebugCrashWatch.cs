using System;
using System.Runtime.InteropServices;
using System.Threading;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Attaches a Win32 debugger to an already-created target
    /// (<c>DebugActiveProcess</c>) and pumps its debug events on a dedicated thread,
    /// so a fault the target hits is observed <b>live</b> — with the faulting
    /// address, registers, faulting instruction bytes, and a stack snapshot — rather
    /// than only surfacing post-mortem as an exit code.
    ///
    /// This is exactly what the suspended-launch startup trace was missing. That
    /// path runs the target free (<c>CREATE_SUSPENDED</c> + <c>ResumeThread</c>, no
    /// debugger), so when a spliced hook corrupted the target the access violation
    /// killed it with the fault invisible — "the suspended-launch path isn't a
    /// debugger, so the fault wasn't caught live". Attaching this watch <em>after</em>
    /// the hooks are armed but <em>before</em> the main thread is resumed keeps every
    /// existing arming/poll path intact and just adds a debugger on the side that
    /// catches the crash and hands the caller what it needs to attribute it.
    ///
    /// It deliberately does <b>not</b> try to resurrect the crashing run: by the time
    /// a deferred access violation is delivered the bad pointer is already in flight,
    /// so retrying the faulting instruction would only re-fault. It catches and
    /// reports the fault (with a stack snapshot to pin which hooked function was
    /// executing), then hands the exception back to the target so its outcome matches
    /// reality. The caller uses the attribution to exclude the culprit hook and
    /// relaunch cleanly — converging on a working hook set across a few attempts.
    ///
    /// As the Win32 debug API requires, every debug call (<c>DebugActiveProcess</c> /
    /// <c>WaitForDebugEvent</c> / <c>ContinueDebugEvent</c> / <c>DebugActiveProcessStop</c>)
    /// runs on the single owned thread.
    /// </summary>
    public sealed class DebugCrashWatch : IDisposable
    {
        /// <summary>A reportable fault caught in the target.</summary>
        public sealed class CrashInfo
        {
            public uint Code;                                  // exception code, e.g. 0xC0000005
            public ulong FaultIp;                              // faulting instruction address
            public string Line = "";                           // one-line diagnostic (DebugExceptionInfo)
            public ulong[] StackWords = Array.Empty<ulong>();  // words from the crashing thread's RSP upward
        }

        public event Action<string>? Log;
        public event Action<CrashInfo>? Crash; // raised ON THE WATCH THREAD while the target is frozen
        public event Action<uint>? Exited;     // target exit code, raised once when the process ends

        private readonly int _pid;
        private readonly int _stackWords;
        private Thread? _thread;
        private volatile bool _stop;
        private readonly ManualResetEventSlim _ready = new(false);
        private volatile bool _attachOk;

        public DebugCrashWatch(int pid, int stackWords = 256)
        {
            _pid = pid;
            _stackWords = stackWords;
        }

        /// <summary>Start the debugger thread (non-blocking).</summary>
        public void Start()
        {
            _thread = new Thread(Run) { IsBackground = true, Name = "CDA startup crash watch" };
            _thread.Start();
        }

        /// <summary>
        /// Block until the debugger has attached and its event pump is live (so the
        /// caller can safely resume the target), or <paramref name="timeoutMs"/>
        /// elapses. Returns true only if the attach succeeded.
        /// </summary>
        public bool WaitUntilAttached(int timeoutMs)
        {
            _ready.Wait(timeoutMs);
            return _attachOk;
        }

        /// <summary>Ask the loop to detach (leaving the target running) and end. Non-blocking.</summary>
        public void Stop() => _stop = true;

        public void Dispose() => _stop = true;

        private void Run()
        {
            // DEBUG_EVENT: a 3-DWORD header (code, pid, tid) then a pointer-aligned
            // union — offset 16 on an x64 host, 12 on x86 — mirroring the U used by
            // the other debug loops and by DebugExceptionInfo.
            IntPtr evt = Marshal.AllocHGlobal(4096);
            int U = IntPtr.Size == 8 ? 16 : 12;
            bool attached = false;
            bool processGone = false;
            try
            {
                if (!NativeMethods.DebugActiveProcess((uint)_pid))
                {
                    Log?.Invoke($"crash watch: DebugActiveProcess failed (error {Marshal.GetLastWin32Error()}); running without live fault capture.");
                    _attachOk = false;
                    _ready.Set();
                    return;
                }
                attached = true;
                // If CDA dies, don't take the debuggee down with it.
                NativeMethods.DebugSetProcessKillOnExit(false);
                _attachOk = true;
                _ready.Set(); // the caller may now resume the target

                bool firstBreakpoint = false;
                ulong lastFaultIp = 0;
                uint lastFaultCode = 0;
                bool haveLast = false;
                int bpNotes = 0;

                while (true)
                {
                    if (!NativeMethods.WaitForDebugEvent(evt, 200))
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err == NativeMethods.ERROR_SEM_TIMEOUT)
                        {
                            if (_stop) break;
                            continue;
                        }
                        Log?.Invoke($"crash watch: WaitForDebugEvent error {err}");
                        break;
                    }

                    uint code = (uint)Marshal.ReadInt32(evt, 0);
                    uint evtPid = (uint)Marshal.ReadInt32(evt, 4);
                    uint evtTid = (uint)Marshal.ReadInt32(evt, 8);
                    uint cont = NativeMethods.DBG_CONTINUE;

                    if (code == NativeMethods.EXIT_PROCESS_DEBUG_EVENT)
                    {
                        uint exit = (uint)Marshal.ReadInt32(evt, U); // EXIT_PROCESS_DEBUG_INFO.dwExitCode
                        NativeMethods.ContinueDebugEvent(evtPid, evtTid, NativeMethods.DBG_CONTINUE);
                        processGone = true;
                        try { Exited?.Invoke(exit); } catch { }
                        return;
                    }

                    if (code == NativeMethods.EXCEPTION_DEBUG_EVENT)
                    {
                        uint exCode = (uint)Marshal.ReadInt32(evt, U); // EXCEPTION_RECORD.ExceptionCode
                        bool isBp = exCode == NativeMethods.EXCEPTION_BREAKPOINT ||
                                    exCode == NativeMethods.STATUS_WX86_BREAKPOINT;
                        int firstChance = Marshal.ReadInt32(evt, U + (IntPtr.Size == 8 ? 152 : 80)); // dwFirstChance
                        ulong faultIp = (ulong)Marshal.ReadIntPtr(evt, U + 8 + IntPtr.Size).ToInt64();

                        if (isBp && !firstBreakpoint)
                        {
                            // The first breakpoint is the debugger-attach breakin (the
                            // OS injects a thread that runs int3); swallow it silently.
                            firstBreakpoint = true;
                        }
                        else if (isBp && firstChance != 0)
                        {
                            // A first-chance int3 the program steps past, NOT a crash: a
                            // debugger rendezvous (CC EB 00 …, executed only because we
                            // attached) or a soft integrity check. We never insert int3s
                            // ourselves, so this is the target's own original code — RIP
                            // already sits past it, so DBG_CONTINUE resumes correctly.
                            // Note it sparingly; if it is genuinely fatal it returns
                            // unhandled (last-chance) and is reported below.
                            if (bpNotes < 8)
                            {
                                Log?.Invoke($"debug breakpoint (int3) at 0x{faultIp:X} (first-chance) — continued (debugger rendezvous / integrity check, not a CDA fault).");
                                bpNotes++;
                            }
                            cont = NativeMethods.DBG_CONTINUE;
                        }
                        else if (DebugExceptionInfo.IsCrash(exCode) || isBp)
                        {
                            // A genuine fault (or an unhandled, last-chance int3). Format
                            // returns null for a first-chance access violation a program
                            // may still handle itself; in that case wait for the last-
                            // chance pass. Skip a fault already reported at the same
                            // address — a code fatal even first-chance surfaces again
                            // last-chance.
                            bool dup = haveLast && faultIp == lastFaultIp && exCode == lastFaultCode;
                            string? line = dup ? null : DebugExceptionInfo.Format(evt, U, exCode, (int)evtPid);
                            if (line != null)
                            {
                                lastFaultIp = faultIp;
                                lastFaultCode = exCode;
                                haveLast = true;
                                var info = new CrashInfo
                                {
                                    Code = exCode,
                                    FaultIp = faultIp,
                                    Line = line,
                                    StackWords = CaptureStack(evtTid),
                                };
                                try { Crash?.Invoke(info); } catch { }

                                // Close the fatally-faulted target cleanly rather than
                                // leaving it stuck at a WER "program has stopped working"
                                // dialog that never closes. The fault is already reported
                                // and the process was going to die anyway; this also lets
                                // the auto-bisection see the crash promptly via a clean exit.
                                try { TargetProcess.Kill((int)evtPid); } catch { }
                            }
                            // Hand the (already-fatal) exception back to the target.
                            cont = NativeMethods.DBG_EXCEPTION_NOT_HANDLED;
                        }
                        else
                        {
                            // A first-chance AV/divide a runtime raises and handles, or a
                            // C++/CLR exception (0xExxxxxxx): pass it through untouched.
                            cont = NativeMethods.DBG_EXCEPTION_NOT_HANDLED;
                        }
                    }

                    NativeMethods.ContinueDebugEvent(evtPid, evtTid, cont);
                    if (_stop) break;
                }
            }
            catch (Exception ex)
            {
                Log?.Invoke("crash watch error: " + ex.Message);
            }
            finally
            {
                if (attached && !processGone)
                {
                    try { NativeMethods.DebugActiveProcessStop((uint)_pid); } catch { }
                }
                Marshal.FreeHGlobal(evt);
                _ready.Set(); // unblock any WaitUntilAttached even on an early failure
            }
        }

        // Snapshot the crashing thread's stack (words from RSP upward) so the caller
        // can find which hooked function still has a frame on it. The target is frozen
        // at the debug event, so the read is consistent. x64 host only — a WOW64
        // thread's 64-bit RSP isn't its 32-bit stack, but attribution simply finds no
        // matching frame there and the caller falls back to the faulting-IP signal.
        private ulong[] CaptureStack(uint tid)
        {
            try
            {
                if (!Environment.Is64BitProcess) return Array.Empty<ulong>();
                IntPtr h = NativeMethods.OpenThread(NativeMethods.THREAD_GET_CONTEXT, false, tid);
                if (h == IntPtr.Zero) return Array.Empty<ulong>();
                try
                {
                    using var ctx = ThreadContextX64.Capture(h);
                    if (ctx == null || ctx.Rsp == 0) return Array.Empty<ulong>();
                    using var tp = TargetProcess.Attach(_pid, forWrite: false);
                    byte[] buf = new byte[_stackWords * 8];
                    int n = tp.ReadMemory(ctx.Rsp, buf);
                    if (n < 8) return Array.Empty<ulong>();
                    int words = n / 8;
                    var result = new ulong[words];
                    for (int i = 0; i < words; i++) result[i] = BitConverter.ToUInt64(buf, i * 8);
                    return result;
                }
                finally { NativeMethods.CloseHandle(h); }
            }
            catch { return Array.Empty<ulong>(); }
        }
    }
}
