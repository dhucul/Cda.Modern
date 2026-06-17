namespace Cda.Core.Cpu
{
    /// <summary>
    /// Who is responsible for cleaning arguments off the stack. The legacy x86
    /// engine detected this per-function (<c>STACK_CLEANUP.BY_CALLED</c> vs
    /// <c>BY_CALLER</c>) to know whether to emit <c>ret n</c> or <c>add esp, n</c>
    /// in its trampolines. x64 has a single uniform convention, so this collapses.
    /// </summary>
    public enum StackCleanup
    {
        Unknown = 0,
        ByCallee, // stdcall / x64: callee adjusts (ret n)
        ByCaller, // cdecl: caller adjusts (add esp, n)
    }

    public enum CallConvention
    {
        Unknown = 0,
        Cdecl,        // x86: all args on stack, caller cleans
        Stdcall,      // x86: all args on stack, callee cleans
        Thiscall,     // x86: ecx = this, rest on stack
        Fastcall,     // x86: ecx, edx, then stack
        Win64,        // x64: rcx, rdx, r8, r9, then stack (+32-byte shadow space)
    }

    /// <summary>
    /// Describes where the integer arguments of a call live, so the capture
    /// decoder can recover them from a <see cref="RegisterContext"/> plus the
    /// stack. Register slots are recorded as register names; stack slots as byte
    /// offsets from the stack pointer at entry.
    /// </summary>
    public sealed class ArgumentLayout
    {
        public CallConvention Convention;
        public StackCleanup Cleanup;

        /// <summary>Register names that carry leading integer args, in order.</summary>
        public string[] RegisterArgs = System.Array.Empty<string>();

        /// <summary>Byte offset from the entry stack pointer to the first stack arg.</summary>
        public int FirstStackArgOffset;

        /// <summary>Pointer size in bytes (4 or 8); stack args are this far apart.</summary>
        public int PointerSize;
    }
}
