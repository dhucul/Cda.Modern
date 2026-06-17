using System.Collections.Generic;

namespace Cda.Core.Cpu
{
    /// <summary>
    /// An architecture-neutral snapshot of integer registers at a captured call
    /// boundary. All slots are 64-bit; on x86 only the low 32 bits are
    /// meaningful. The legacy capture stored ecx/edx/eax explicitly — those map
    /// to <see cref="Cx"/>/<see cref="Dx"/>/<see cref="Ax"/> here, while x64 adds
    /// the rest of the argument-passing set.
    /// </summary>
    public struct RegisterContext
    {
        public ulong Ax, Bx, Cx, Dx, Si, Di, Bp, Sp; // *AX..*SP (E** on x86, R** on x64)
        public ulong R8, R9, R10, R11, R12, R13, R14, R15; // x64 only
        public ulong Ip; // instruction pointer

        public IReadOnlyDictionary<string, ulong> AsMap(bool is64)
        {
            var d = new Dictionary<string, ulong>
            {
                [is64 ? "rax" : "eax"] = Ax,
                [is64 ? "rbx" : "ebx"] = Bx,
                [is64 ? "rcx" : "ecx"] = Cx,
                [is64 ? "rdx" : "edx"] = Dx,
                [is64 ? "rsi" : "esi"] = Si,
                [is64 ? "rdi" : "edi"] = Di,
                [is64 ? "rbp" : "ebp"] = Bp,
                [is64 ? "rsp" : "esp"] = Sp,
            };
            if (is64)
            {
                d["r8"] = R8; d["r9"] = R9; d["r10"] = R10; d["r11"] = R11;
                d["r12"] = R12; d["r13"] = R13; d["r14"] = R14; d["r15"] = R15;
            }
            return d;
        }
    }
}
