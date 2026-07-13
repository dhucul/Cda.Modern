using System;

namespace Cda.Core.Engine
{
    /// <summary>
    /// The slice of a thread's CPU context a hardware branch probe needs, independent of
    /// target bitness: read EFLAGS (to evaluate a Jcc's real taken/not-taken) and the
    /// count register (for jcxz/loop), read RIP/EIP (to confirm which armed branch faulted),
    /// and read/write DR6 + the debug-register breakpoints. Implemented by
    /// <see cref="ThreadContextX64"/> (x64) and ThreadContextWow64 (32-bit, phase B), so the
    /// probe logic in <see cref="DialogBranchConfirmer"/> / <c>LaunchApiCapture</c> is
    /// bitness-neutral.
    /// </summary>
    internal interface IThreadContext : IDisposable
    {
        /// <summary>True for an x64 thread, false for a 32-bit (WOW64) thread — the count
        /// register width for loop/jcxz evaluation depends on it.</summary>
        bool Is64 { get; }

        uint EFlags { get; set; }
        ulong Dr6 { get; set; }

        /// <summary>RCX (x64) / ECX (WOW64) — the implicit count for jcxz/loop conditions.</summary>
        ulong CountRegister { get; }

        /// <summary>RIP (x64) / EIP (WOW64) — used to confirm which armed branch faulted.</summary>
        ulong InstructionPointer { get; }

        /// <summary>RSP (x64) / ESP (WOW64) — at a call's entry the top word is the return
        /// address, used to tell an app-originated dialog call from a system-internal one.</summary>
        ulong StackPointer { get; }

        void SetBreakpoints(ulong[] addrs);
        void ClearBreakpoints();
        bool Apply(IntPtr hThread);
    }

    /// <summary>Captures the right per-bitness thread context behind <see cref="IThreadContext"/>.</summary>
    internal static class ThreadContext
    {
        /// <summary>EFLAGS.RF (resume flag) — steps over a code breakpoint without re-firing
        /// it; the same bit on x86 and x64. Setting it does NOT disturb the arithmetic flags.</summary>
        public const uint ResumeFlag = 0x00010000;

        public static IThreadContext? Capture(IntPtr hThread, bool isWow64)
            => isWow64 ? ThreadContextWow64.Capture(hThread) : ThreadContextX64.Capture(hThread);
    }
}
