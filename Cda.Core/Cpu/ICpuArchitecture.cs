using System;
using System.Collections.Generic;
using Cda.Core.Memory;

namespace Cda.Core.Cpu
{
    /// <summary>
    /// The seam that lets one engine analyze both 32-bit and 64-bit targets.
    /// Everything the instrumentation pipeline does that differs by architecture
    /// is funneled through this interface, so the rest of the engine (PE parsing,
    /// process I/O, the visualization) stays architecture-agnostic.
    ///
    /// The legacy tool had no such seam: x86 assumptions (EBP frames, fs:[0] SEH,
    /// 5-byte E8 call patching, cdecl/stdcall cleanup detection) were woven
    /// directly through the code, which is why it was x86-only. Concrete
    /// implementations are <see cref="X86Architecture"/> (a port of that logic)
    /// and <see cref="X64Architecture"/> (new work).
    ///
    /// What this seam carries:
    ///   * <b>Inspection</b>: pointer size, register naming, argument layout, and
    ///     argument recovery from a captured register/stack context.
    ///   * <b>Discovery</b>: direct-call scanning and minimum hook length, via the
    ///     shared disassembler (Iced).
    /// The byte-exact instrumentation (entry hooks, capture stubs, trampolines)
    /// lives in the Engine layer (<c>InlineHook</c> + <c>CaptureStub</c>) and needs
    /// only <see cref="Is64Bit"/> from this seam.
    /// </summary>
    public interface ICpuArchitecture
    {
        string Name { get; }
        bool Is64Bit { get; }
        int PointerSize { get; }

        // --- Inspection tier -------------------------------------------------

        /// <summary>Default argument layout for the platform's standard convention.</summary>
        ArgumentLayout GetDefaultArgumentLayout();

        /// <summary>
        /// Recover up to <paramref name="count"/> integer arguments for a call,
        /// given the register snapshot at entry and a reader for the target's
        /// stack. Pure inspection: no code is written into the target.
        /// </summary>
        ulong[] RecoverIntegerArguments(
            in RegisterContext ctx, ArgumentLayout layout, IMemorySource stack, int count);

        // --- Discovery tier --------------------------------------------------

        /// <summary>
        /// Scan a byte range for call instructions, returning (siteAddress,
        /// targetAddress) pairs for direct calls. Indirect calls report a target
        /// of 0. Requires the disassembler; throws until that phase lands.
        /// </summary>
        IEnumerable<(ulong Site, ulong Target)> FindDirectCalls(
            ReadOnlyMemory<byte> code, ulong codeBase);

        /// <summary>
        /// Like <see cref="FindDirectCalls(ReadOnlyMemory{byte}, ulong)"/> but reads the
        /// code <b>on demand</b> from <paramref name="memory"/> over <paramref name="length"/>
        /// bytes starting at <paramref name="start"/>, never copying the whole range. This
        /// lets discovery cover a very large code section (e.g. a memory-mapped module)
        /// with flat memory use. <paramref name="codeBase"/> is the VA the first byte maps to.
        /// </summary>
        IEnumerable<(ulong Site, ulong Target)> FindDirectCalls(
            IMemorySource memory, ulong start, long length, ulong codeBase);

        /// <summary>
        /// Number of bytes that must be overwritten at <paramref name="address"/>
        /// to install an entry hook without splitting an instruction (the patch
        /// must cover whole instructions). Requires the disassembler.
        /// </summary>
        int GetMinimumHookLength(IMemorySource memory, ulong address);
    }

    public static class CpuArchitectures
    {
        public static ICpuArchitecture For(bool is64Bit) =>
            is64Bit ? new X64Architecture() : new X86Architecture();
    }
}
