using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Cda.Core.Memory;

namespace Cda.Core.Cpu
{
    /// <summary>
    /// 64-bit x64 architecture: the inspection and discovery seams for x64 (the
    /// legacy engine had no x64 path). The byte-exact entry hooks and capture
    /// stubs live in the Engine layer (InlineHook + CaptureStub). Key departures
    /// from x86 that this seam encodes:
    ///
    ///   * <b>Calling convention</b> is uniform (Win64): the first four integer
    ///     args are in RCX, RDX, R8, R9; floats in XMM0-3; the rest spill to the
    ///     stack. The caller reserves 32 bytes of "shadow space" above the return
    ///     address, so the first *stack* arg sits at [rsp + 8 (ret) + 32].
    ///   * <b>No frame pointer guarantee</b>: RBP is a general register, so stack
    ///     args/locals are recovered from unwind info (.pdata/.xdata), not [rbp+n].
    ///   * <b>Exceptions are table-based</b> (.pdata/.xdata), not an fs:[0] chain.
    ///   * <b>Hooks need longer detours</b>: a rel32 jmp only reaches +/-2GB, so a
    ///     far hook uses an indirect jump (FF 25 + RIP-relative 64-bit pointer) and
    ///     a 14-byte minimum patch.
    /// </summary>
    public sealed class X64Architecture : ICpuArchitecture
    {
        public string Name => "x64";
        public bool Is64Bit => true;
        public int PointerSize => 8;

        public const int ShadowSpace = 32;

        public ArgumentLayout GetDefaultArgumentLayout() => new()
        {
            Convention = CallConvention.Win64,
            Cleanup = StackCleanup.ByCallee, // uniform: caller-allocated, no per-call cleanup variance
            RegisterArgs = new[] { "rcx", "rdx", "r8", "r9" },
            // At entry, [rsp] = return address; shadow space follows; first stack
            // arg is the 5th integer arg at [rsp + 8 + 32].
            FirstStackArgOffset = 8 + ShadowSpace,
            PointerSize = 8,
        };

        public ulong[] RecoverIntegerArguments(
            in RegisterContext ctx, ArgumentLayout layout, IMemorySource stack, int count)
        {
            if (count <= 0) return Array.Empty<ulong>();
            var args = new ulong[count];

            int reg = 0;
            for (; reg < layout.RegisterArgs.Length && reg < count; reg++)
            {
                args[reg] = layout.RegisterArgs[reg].ToLowerInvariant() switch
                {
                    "rcx" => ctx.Cx,
                    "rdx" => ctx.Dx,
                    "r8" => ctx.R8,
                    "r9" => ctx.R9,
                    _ => 0
                };
            }

            Span<byte> slot = stackalloc byte[8];
            for (int i = reg; i < count; i++)
            {
                // 5th arg onward; index past the register args into the stack.
                ulong addr = ctx.Sp + (ulong)(layout.FirstStackArgOffset + (i - reg) * 8);
                args[i] = stack.ReadMemory(addr, slot) == 8
                    ? BinaryPrimitives.ReadUInt64LittleEndian(slot)
                    : 0;
            }
            return args;
        }

        public IEnumerable<(ulong Site, ulong Target)> FindDirectCalls(ReadOnlyMemory<byte> code, ulong codeBase)
            => Disasm.FindDirectCalls(64, code, codeBase);

        public IEnumerable<(ulong Site, ulong Target)> FindDirectCalls(
            IMemorySource memory, ulong start, long length, ulong codeBase)
            => Disasm.FindDirectCalls(64, memory, start, length, codeBase);

        public int GetMinimumHookLength(IMemorySource memory, ulong address)
            => Disasm.HookLength(64, memory, address, 14); // FF25 + abs64 indirect jmp = 14 bytes
    }
}
