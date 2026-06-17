using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Cda.Core.Memory;

namespace Cda.Core.Cpu
{
    /// <summary>
    /// 32-bit x86 architecture: the inspection and discovery seams for x86.
    /// Argument layout/recovery follow cdecl/stdcall (everything on the stack;
    /// ecx/edx for thiscall/fastcall), and direct-call scanning + hook-length run
    /// through Iced. The byte-exact entry hooks and capture stubs live in the
    /// Engine layer (InlineHook + CaptureStub), so no instrumentation methods are
    /// needed here.
    /// </summary>
    public sealed class X86Architecture : ICpuArchitecture
    {
        public string Name => "x86";
        public bool Is64Bit => false;
        public int PointerSize => 4;

        public ArgumentLayout GetDefaultArgumentLayout() => new()
        {
            Convention = CallConvention.Cdecl,
            Cleanup = StackCleanup.ByCaller,
            RegisterArgs = Array.Empty<string>(), // cdecl/stdcall: everything on the stack
            FirstStackArgOffset = 4,              // first arg sits just past the return address
            PointerSize = 4,
        };

        public ulong[] RecoverIntegerArguments(
            in RegisterContext ctx, ArgumentLayout layout, IMemorySource stack, int count)
        {
            if (count <= 0) return Array.Empty<ulong>();
            var args = new ulong[count];

            // Leading register args (thiscall: ecx; fastcall: ecx, edx).
            int reg = 0;
            for (; reg < layout.RegisterArgs.Length && reg < count; reg++)
            {
                args[reg] = layout.RegisterArgs[reg].ToLowerInvariant() switch
                {
                    "ecx" => ctx.Cx,
                    "edx" => ctx.Dx,
                    "eax" => ctx.Ax,
                    _ => 0
                } & 0xFFFFFFFFUL;
            }

            // Remaining args from the stack at [esp + FirstStackArgOffset + i*4].
            Span<byte> slot = stackalloc byte[4];
            for (int i = reg; i < count; i++)
            {
                ulong addr = ctx.Sp + (ulong)(layout.FirstStackArgOffset + (i - reg) * 4);
                args[i] = stack.ReadMemory(addr, slot) == 4
                    ? BinaryPrimitives.ReadUInt32LittleEndian(slot)
                    : 0;
            }
            return args;
        }

        public IEnumerable<(ulong Site, ulong Target)> FindDirectCalls(ReadOnlyMemory<byte> code, ulong codeBase)
            => Disasm.FindDirectCalls(32, code, codeBase);

        public IEnumerable<(ulong Site, ulong Target)> FindDirectCalls(
            IMemorySource memory, ulong start, long length, ulong codeBase)
            => Disasm.FindDirectCalls(32, memory, start, length, codeBase);

        public int GetMinimumHookLength(IMemorySource memory, ulong address)
            => Disasm.HookLength(32, memory, address, 5); // E9 rel32 jmp = 5 bytes
    }
}
