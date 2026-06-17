using System;
using System.Runtime.InteropServices;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// A thin wrapper over an x64 <c>CONTEXT</c> buffer for reading/writing the
    /// few fields hardware-breakpoint capture needs: the debug registers (DR0–DR3
    /// + DR7 to arm execution breakpoints, DR6 to see which fired), the integer
    /// argument registers (RCX/RDX/R8/R9), and the control registers (RSP/RIP/
    /// EFlags). The native CONTEXT is large (1232 bytes) and must be 16-byte
    /// aligned for <c>GetThreadContext</c>/<c>SetThreadContext</c>; rather than
    /// declare the whole struct we allocate an aligned block and access fields by
    /// their documented offsets (the same by-offset style the debug loops use for
    /// DEBUG_EVENT). x64 only — a WOW64 (32-bit) thread needs WOW64_CONTEXT via
    /// Wow64Get/SetThreadContext, so the hardware-breakpoint mode refuses WOW64
    /// targets upstream.
    /// </summary>
    internal sealed class ThreadContextX64 : IDisposable
    {
        // x64 CONTEXT field offsets (bytes).
        private const int OFF_ContextFlags = 0x30;
        private const int OFF_EFlags = 0x44;
        private const int OFF_Dr0 = 0x48;
        private const int OFF_Dr1 = 0x50;
        private const int OFF_Dr2 = 0x58;
        private const int OFF_Dr3 = 0x60;
        private const int OFF_Dr6 = 0x68;
        private const int OFF_Dr7 = 0x70;
        private const int OFF_Rcx = 0x80;
        private const int OFF_Rdx = 0x88;
        private const int OFF_Rsp = 0x98;
        private const int OFF_R8 = 0xB8;
        private const int OFF_R9 = 0xC0;
        private const int OFF_Rip = 0xF8;
        // Full integer register file — read only for the crash-context dump.
        private const int OFF_Rax = 0x78;
        private const int OFF_Rbx = 0x90;
        private const int OFF_Rbp = 0xA0;
        private const int OFF_Rsi = 0xA8;
        private const int OFF_Rdi = 0xB0;
        private const int OFF_R10 = 0xC8;
        private const int OFF_R11 = 0xD0;
        private const int OFF_R12 = 0xD8;
        private const int OFF_R13 = 0xE0;
        private const int OFF_R14 = 0xE8;
        private const int OFF_R15 = 0xF0;
        private const int CONTEXT_SIZE = 0x4D0; // 1232

        // CONTEXT flag bits (AMD64).
        private const uint CONTEXT_AMD64 = 0x00100000;
        private const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1;
        private const uint CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2;
        private const uint CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10;

        // What we always want captured/applied: control + integer + debug regs.
        private const uint WANT = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;

        // EFLAGS.RF (resume flag): suppresses an instruction breakpoint for exactly
        // the next instruction, so a thread can step off a code breakpoint without
        // immediately re-triggering it.
        public const uint ResumeFlag = 0x00010000;

        private IntPtr _raw;          // unaligned allocation base (to free)
        private readonly IntPtr _ctx; // 16-byte aligned pointer into _raw

        private ThreadContextX64(IntPtr raw, IntPtr ctx) { _raw = raw; _ctx = ctx; }

        private static ThreadContextX64 Alloc()
        {
            IntPtr raw = Marshal.AllocHGlobal(CONTEXT_SIZE + 16);
            long aligned = ((long)raw + 15) & ~15L;
            var c = new ThreadContextX64(raw, (IntPtr)aligned);
            for (int i = 0; i < CONTEXT_SIZE; i += 8) Marshal.WriteInt64(c._ctx, i, 0);
            return c;
        }

        /// <summary>GetThreadContext into a fresh buffer; null if the call fails.</summary>
        public static ThreadContextX64? Capture(IntPtr hThread)
        {
            var c = Alloc();
            c.ContextFlags = WANT;
            if (!NativeMethods.GetThreadContext(hThread, c._ctx)) { c.Dispose(); return null; }
            return c;
        }

        /// <summary>One-line hex dump of the integer registers, for a crash context.</summary>
        public string FormatIntegerRegisters()
        {
            ulong Q(int off) => (ulong)Marshal.ReadInt64(_ctx, off);
            return
                $"rax={Q(OFF_Rax):X} rbx={Q(OFF_Rbx):X} rcx={Q(OFF_Rcx):X} rdx={Q(OFF_Rdx):X} " +
                $"rsi={Q(OFF_Rsi):X} rdi={Q(OFF_Rdi):X} rbp={Q(OFF_Rbp):X} rsp={Q(OFF_Rsp):X} " +
                $"r8={Q(OFF_R8):X} r9={Q(OFF_R9):X} r10={Q(OFF_R10):X} r11={Q(OFF_R11):X} " +
                $"r12={Q(OFF_R12):X} r13={Q(OFF_R13):X} r14={Q(OFF_R14):X} r15={Q(OFF_R15):X}";
        }

        /// <summary>SetThreadContext from this buffer.</summary>
        public bool Apply(IntPtr hThread)
        {
            ContextFlags = WANT;
            return NativeMethods.SetThreadContext(hThread, _ctx);
        }

        private uint ContextFlags
        {
            get => (uint)Marshal.ReadInt32(_ctx, OFF_ContextFlags);
            set => Marshal.WriteInt32(_ctx, OFF_ContextFlags, (int)value);
        }

        public uint EFlags
        {
            get => (uint)Marshal.ReadInt32(_ctx, OFF_EFlags);
            set => Marshal.WriteInt32(_ctx, OFF_EFlags, (int)value);
        }

        public ulong Dr6
        {
            get => (ulong)Marshal.ReadInt64(_ctx, OFF_Dr6);
            set => Marshal.WriteInt64(_ctx, OFF_Dr6, (long)value);
        }

        public ulong Rcx => (ulong)Marshal.ReadInt64(_ctx, OFF_Rcx);
        public ulong Rdx => (ulong)Marshal.ReadInt64(_ctx, OFF_Rdx);
        public ulong R8 => (ulong)Marshal.ReadInt64(_ctx, OFF_R8);
        public ulong R9 => (ulong)Marshal.ReadInt64(_ctx, OFF_R9);
        public ulong Rsp => (ulong)Marshal.ReadInt64(_ctx, OFF_Rsp);
        public ulong Rip => (ulong)Marshal.ReadInt64(_ctx, OFF_Rip);

        /// <summary>
        /// Arm DR0..DR(n-1) as 1-byte execute breakpoints at <paramref name="addrs"/>
        /// (at most 4) and enable them in DR7. For an execute breakpoint the R/W and
        /// LEN fields are both 0, so DR7 just needs the local+global enable bits per
        /// register: 1 bp → 0x3, 2 → 0xF, 3 → 0x3F, 4 → 0xFF.
        /// </summary>
        public void SetBreakpoints(ulong[] addrs)
        {
            Marshal.WriteInt64(_ctx, OFF_Dr0, addrs.Length > 0 ? (long)addrs[0] : 0);
            Marshal.WriteInt64(_ctx, OFF_Dr1, addrs.Length > 1 ? (long)addrs[1] : 0);
            Marshal.WriteInt64(_ctx, OFF_Dr2, addrs.Length > 2 ? (long)addrs[2] : 0);
            Marshal.WriteInt64(_ctx, OFF_Dr3, addrs.Length > 3 ? (long)addrs[3] : 0);

            ulong dr7 = 0;
            int n = Math.Min(addrs.Length, 4);
            for (int i = 0; i < n; i++)
                dr7 |= (1UL << (i * 2)) | (1UL << (i * 2 + 1)); // Ln + Gn; R/W=00 (exec), LEN=00 (1 byte)
            Marshal.WriteInt64(_ctx, OFF_Dr7, (long)dr7);
            Dr6 = 0;
        }

        /// <summary>Disable all four breakpoints (clears the addresses, DR7 and DR6).</summary>
        public void ClearBreakpoints()
        {
            Marshal.WriteInt64(_ctx, OFF_Dr0, 0);
            Marshal.WriteInt64(_ctx, OFF_Dr1, 0);
            Marshal.WriteInt64(_ctx, OFF_Dr2, 0);
            Marshal.WriteInt64(_ctx, OFF_Dr3, 0);
            Marshal.WriteInt64(_ctx, OFF_Dr7, 0);
            Dr6 = 0;
        }

        public void Dispose()
        {
            if (_raw != IntPtr.Zero) { Marshal.FreeHGlobal(_raw); _raw = IntPtr.Zero; }
        }
    }
}
