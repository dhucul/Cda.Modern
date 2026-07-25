using System;
using System.Runtime.InteropServices;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// The WOW64 (32-bit target) counterpart of <see cref="ThreadContextX64"/>: a thin
    /// by-offset wrapper over a <c>WOW64_CONTEXT</c> buffer for the few fields the hardware
    /// branch probe needs — EFLAGS, ECX (the jcxz/loop count), EIP, and the debug registers
    /// (DR0–DR3 + DR7 to arm execute breakpoints, DR6 to see which fired). Read/written with
    /// <c>Wow64Get/SetThreadContext</c> so a 32-bit thread's real 32-bit register state is
    /// seen from the x64 host (plain Get/SetThreadContext on a WOW64 thread returns the x64
    /// transition context instead). Debug-register semantics are identical to x64 — execute
    /// breakpoint = R/W 00, LEN 00, DR7 low-8 local+global enable bits. Kept behind
    /// <see cref="IThreadContext"/> so the probe logic is bitness-neutral.
    /// </summary>
    internal sealed class ThreadContextWow64 : IThreadContext
    {
        // WOW64_CONTEXT field offsets (bytes). FloatSave (112 B) sits at 0x1C, so the
        // integer/control registers start at 0x9C; the debug registers are at the top.
        private const int OFF_ContextFlags = 0x00;
        private const int OFF_Dr0 = 0x04;
        private const int OFF_Dr1 = 0x08;
        private const int OFF_Dr2 = 0x0C;
        private const int OFF_Dr3 = 0x10;
        private const int OFF_Dr6 = 0x14;
        private const int OFF_Dr7 = 0x18;
        private const int OFF_Ecx = 0xAC;
        private const int OFF_Eip = 0xB8;
        private const int OFF_EFlags = 0xC0;
        private const int OFF_Esp = 0xC4;
        private const int CONTEXT_SIZE = 0x2CC; // 716 (through ExtendedRegisters[512] at 0xCC)

        // CONTEXT flag bits (i386).
        private const uint CONTEXT_i386 = 0x00010000;
        private const uint CONTEXT_CONTROL = CONTEXT_i386 | 0x1;
        private const uint CONTEXT_INTEGER = CONTEXT_i386 | 0x2;
        private const uint CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10;
        private const uint WANT = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;

        private IntPtr _raw;          // unaligned allocation base (to free)
        private readonly IntPtr _ctx; // aligned pointer into _raw

        private ThreadContextWow64(IntPtr raw, IntPtr ctx) { _raw = raw; _ctx = ctx; }

        private static ThreadContextWow64 Alloc()
        {
            IntPtr raw = Marshal.AllocHGlobal(CONTEXT_SIZE + 16);
            long aligned = ((long)raw + 15) & ~15L;
            var c = new ThreadContextWow64(raw, (IntPtr)aligned);
            for (int i = 0; i < CONTEXT_SIZE; i += 4) Marshal.WriteInt32(c._ctx, i, 0);
            return c;
        }

        /// <summary>Wow64GetThreadContext into a fresh buffer; null if the call fails.</summary>
        public static ThreadContextWow64? Capture(IntPtr hThread)
        {
            var c = Alloc();
            c.ContextFlags = WANT;
            if (!NativeMethods.Wow64GetThreadContext(hThread, c._ctx)) { c.Dispose(); return null; }
            return c;
        }

        public bool Apply(IntPtr hThread)
        {
            ContextFlags = WANT;
            return NativeMethods.Wow64SetThreadContext(hThread, _ctx);
        }

        private uint ContextFlags
        {
            get => (uint)Marshal.ReadInt32(_ctx, OFF_ContextFlags);
            set => Marshal.WriteInt32(_ctx, OFF_ContextFlags, (int)value);
        }

        public bool Is64 => false;

        public uint EFlags
        {
            get => (uint)Marshal.ReadInt32(_ctx, OFF_EFlags);
            set => Marshal.WriteInt32(_ctx, OFF_EFlags, (int)value);
        }

        public ulong Dr6
        {
            get => (uint)Marshal.ReadInt32(_ctx, OFF_Dr6);
            set => Marshal.WriteInt32(_ctx, OFF_Dr6, unchecked((int)(uint)value));
        }

        public ulong CountRegister => (uint)Marshal.ReadInt32(_ctx, OFF_Ecx);
        public ulong InstructionPointer => (uint)Marshal.ReadInt32(_ctx, OFF_Eip);
        public ulong StackPointer => (uint)Marshal.ReadInt32(_ctx, OFF_Esp);

        public void SetBreakpoints(ulong[] addrs)
        {
            Marshal.WriteInt32(_ctx, OFF_Dr0, addrs.Length > 0 ? unchecked((int)(uint)addrs[0]) : 0);
            Marshal.WriteInt32(_ctx, OFF_Dr1, addrs.Length > 1 ? unchecked((int)(uint)addrs[1]) : 0);
            Marshal.WriteInt32(_ctx, OFF_Dr2, addrs.Length > 2 ? unchecked((int)(uint)addrs[2]) : 0);
            Marshal.WriteInt32(_ctx, OFF_Dr3, addrs.Length > 3 ? unchecked((int)(uint)addrs[3]) : 0);

            uint dr7 = (uint)Marshal.ReadInt32(_ctx, OFF_Dr7) & 0x0000FF00U;
            int n = Math.Min(addrs.Length, 4);
            for (int i = 0; i < n; i++)
                dr7 |= (1U << (i * 2)) | (1U << (i * 2 + 1)); // Ln + Gn; R/W=00 (exec), LEN=00 (1 byte)
            Marshal.WriteInt32(_ctx, OFF_Dr7, unchecked((int)dr7));
            Marshal.WriteInt32(_ctx, OFF_Dr6, 0);
        }

        public DebugRegisterState CaptureDebugRegisters() => new(
            (uint)Marshal.ReadInt32(_ctx, OFF_Dr0),
            (uint)Marshal.ReadInt32(_ctx, OFF_Dr1),
            (uint)Marshal.ReadInt32(_ctx, OFF_Dr2),
            (uint)Marshal.ReadInt32(_ctx, OFF_Dr3),
            (uint)Marshal.ReadInt32(_ctx, OFF_Dr6),
            (uint)Marshal.ReadInt32(_ctx, OFF_Dr7));

        public void RestoreDebugRegisters(DebugRegisterState state)
        {
            Marshal.WriteInt32(_ctx, OFF_Dr0, unchecked((int)(uint)state.Dr0));
            Marshal.WriteInt32(_ctx, OFF_Dr1, unchecked((int)(uint)state.Dr1));
            Marshal.WriteInt32(_ctx, OFF_Dr2, unchecked((int)(uint)state.Dr2));
            Marshal.WriteInt32(_ctx, OFF_Dr3, unchecked((int)(uint)state.Dr3));
            Marshal.WriteInt32(_ctx, OFF_Dr6, unchecked((int)(uint)state.Dr6));
            Marshal.WriteInt32(_ctx, OFF_Dr7, unchecked((int)(uint)state.Dr7));
        }

        public void Dispose()
        {
            if (_raw != IntPtr.Zero) { Marshal.FreeHGlobal(_raw); _raw = IntPtr.Zero; }
        }
    }
}
