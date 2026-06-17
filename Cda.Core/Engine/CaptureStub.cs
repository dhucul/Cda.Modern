using System;
using System.Collections.Generic;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Generates the x86 capture stub — the detour body installed at a hooked
    /// function entry. On each call it claims a slot in the ring buffer and
    /// records the call, then chains to the trampoline (which runs the original
    /// stolen instructions and returns into the function body).
    ///
    /// This is the modern, assembler-generated equivalent of the legacy
    /// hand-written injection asm. It captures:
    ///   * timestamp (rdtsc), source (return address), destination,
    ///     stack pointer, and a fixed number of stack arguments,
    ///   * a fixed-depth snapshot of the stack from the entry SP upward, so the
    ///     host can walk past runtime/CRT wrappers back to the program's own code,
    ///   * claims its slot with <c>lock xadd</c> so concurrent threads are safe.
    /// It does NOT yet follow pointer arguments in-target (dereferences) or install
    /// an exception guard; those are layered on host-side / later.
    ///
    /// Record layout matches <see cref="RingBufferReader"/>.
    /// </summary>
    public static class CaptureStub
    {
        /// <summary>
        /// Stack words captured per call (each pointer-sized, stored zero-extended
        /// to 64-bit), read from the entry SP upward — toward the caller's already-
        /// committed frames, so the read is always safe. This is the depth the host
        /// can walk for two things: recovering the program's own caller chain past
        /// runtime/CRT wrapper frames (the "Called by" tree and per-call "Call
        /// stack"), and decoding string arguments that sit past the few captured
        /// integer args (argument <c>i</c> lives at <c>snapshot[i+1]</c>). 64 words
        /// (512 bytes on x64, 256 on x86) reaches up to ~arg63 and deeper wrapper
        /// stacks; RecordSize(4) is then 588 bytes, so a 65,536-slot ring is ~38 MB
        /// in the target. Raising this deepens both at a linear memory cost; because
        /// it changes the record format, re-run the capture Self-test after changing
        /// it.
        /// </summary>
        public const int StackSlots = 64;

        /// <summary>Bytes a record occupies for the given fixed argument count.</summary>
        public static int RecordSize(int argCount)
            => 36                 // timestamp + source + destination + stackPointer + argCount
             + argCount * 8        // integer args
             + 4                   // stackSlots count
             + StackSlots * 8      // stack snapshot
             + 4;                  // derefCount

        /// <summary>
        /// Build the stub for the address it will be written to. Absolute target
        /// addresses are embedded as immediates, so the stub is specific to this
        /// allocation.
        /// </summary>
        public static byte[] BuildX86(
            ulong stubAddress, ulong destination, ulong controlAddress,
            ulong bufferAddress, ulong trampolineAddress, int argCount, int slotCount)
        {
            int recordSize = RecordSize(argCount);
            int mask = slotCount - 1; // slotCount is a power of two
            int ctrl = unchecked((int)(uint)controlAddress);
            int buf = unchecked((int)(uint)bufferAddress);
            int dst = unchecked((int)(uint)destination);

            int stackCountOff = 36 + argCount * 8;
            int snapshotOff = stackCountOff + 4;
            int derefCountOff = snapshotOff + StackSlots * 8;

            var a = new Assembler(32);

            // Preserve flags + all GP registers; the function must see its entry
            // state unchanged when we chain to the trampoline.
            a.pushfd();
            a.pushad(); // 32 bytes; with pushfd, original esp = esp + 36

            // Atomically claim a ring slot: eax = our sequence number, claimSeq++.
            // index = seq & (slotCount-1); offset = index * recordSize. slotCount
            // is a power of two, so the offset is always in range — no bounds check
            // and no drop; if the writer laps the reader the oldest slot is reused.
            a.mov(eax, 1);
            a.mov(ebx, ctrl);
            a.@lock.xadd(__dword_ptr[ebx + 8], eax); // eax = old claimSeq
            a.and(eax, mask);                         // slot index
            a.imul(eax, eax, recordSize);             // byte offset into the ring

            a.mov(edi, buf);
            a.add(edi, eax);                   // edi = &slot

            // timestamp (edx:eax)
            a.rdtsc();
            a.mov(__dword_ptr[edi + 0], eax);
            a.mov(__dword_ptr[edi + 4], edx);

            // source = return address at [esp+36]
            a.mov(eax, __dword_ptr[esp + 36]);
            a.mov(__dword_ptr[edi + 8], eax);
            a.mov(__dword_ptr[edi + 12], 0);

            // destination (constant)
            a.mov(__dword_ptr[edi + 16], dst);
            a.mov(__dword_ptr[edi + 20], 0);

            // stack pointer at entry = esp + 36
            a.lea(eax, __[esp + 36]);
            a.mov(__dword_ptr[edi + 24], eax);
            a.mov(__dword_ptr[edi + 28], 0);

            // argCount
            a.mov(__dword_ptr[edi + 32], argCount);

            // stack args: arg_i at [esp + 40 + i*4]; stored as u64 (hi = 0)
            for (int i = 0; i < argCount; i++)
            {
                a.mov(eax, __dword_ptr[esp + 40 + i * 4]);
                a.mov(__dword_ptr[edi + 36 + i * 8], eax);
                a.mov(__dword_ptr[edi + 40 + i * 8], 0);
            }

            // stack snapshot: copy StackSlots words from the entry stack upward.
            // esi/edx/eax/ecx are all preserved by pushad; edi (the record base)
            // is kept for the derefCount write after the loop.
            a.mov(__dword_ptr[edi + stackCountOff], StackSlots);
            a.lea(esi, __[esp + 36]);              // source = entry esp
            a.lea(edx, __[edi + snapshotOff]);     // dest = snapshot region
            a.mov(ecx, StackSlots);
            var copy = a.CreateLabel();
            a.Label(ref copy);
            a.mov(eax, __dword_ptr[esi]);
            a.mov(__dword_ptr[edx + 0], eax);
            a.mov(__dword_ptr[edx + 4], 0);        // zero-extend to 64-bit
            a.add(esi, 4);
            a.add(edx, 8);
            a.dec(ecx);
            a.jnz(copy);

            // derefCount = 0 (no in-target pointer-following in this version)
            a.mov(__dword_ptr[edi + derefCountOff], 0);

            a.popad();
            a.popfd();
            a.jmp(trampolineAddress);

            var writer = new Cda.Core.Cpu.ListCodeWriter();
            a.Assemble(writer, stubAddress);
            return writer.Bytes.ToArray();
        }

        /// <summary>Dispatch to the architecture-appropriate stub builder.</summary>
        public static byte[] Build(
            bool is64Bit, ulong stubAddress, ulong destination, ulong controlAddress,
            ulong bufferAddress, ulong trampolineAddress, int argCount, int slotCount)
            => is64Bit
                ? BuildX64(stubAddress, destination, controlAddress, bufferAddress, trampolineAddress, argCount, slotCount)
                : BuildX86(stubAddress, destination, controlAddress, bufferAddress, trampolineAddress, argCount, slotCount);

        /// <summary>
        /// Build the x64 capture stub. Differences from x86: registers are saved
        /// individually (no pushad), the first four args come from RCX/RDX/R8/R9,
        /// stack args start past the 32-byte shadow space, addresses are loaded
        /// into registers (no 64-bit memory immediates), and the chain-back uses a
        /// RIP-relative indirect jump because every register must be restored
        /// first.
        /// </summary>
        public static byte[] BuildX64(
            ulong stubAddress, ulong destination, ulong controlAddress,
            ulong bufferAddress, ulong trampolineAddress, int argCount, int slotCount)
        {
            int recordSize = RecordSize(argCount);
            int mask = slotCount - 1; // slotCount is a power of two

            int stackCountOff = 36 + argCount * 8;
            int snapshotOff = stackCountOff + 4;
            int derefCountOff = snapshotOff + StackSlots * 8;

            var a = new Assembler(64);

            // Save flags + the registers we touch. 8 pushes = 64 bytes, so the
            // entry rsp = current rsp + 64. We push rcx/rdx/r8/r9 so we have a
            // stable place to read the register args from and to restore them.
            a.push(rax);   // [rsp+56] after all pushes
            a.push(rbx);   // [rsp+48]
            a.push(rcx);   // [rsp+40]  arg0
            a.push(rdx);   // [rsp+32]  arg1
            a.push(r8);    // [rsp+24]  arg2
            a.push(r9);    // [rsp+16]  arg3
            a.push(rdi);   // [rsp+8]
            a.pushfq();    // [rsp+0]
            // entry return address (source) = [rsp+64]; stack arg5 = [rsp+104]

            a.mov(rbx, controlAddress);
            a.mov(eax, 1);
            a.@lock.xadd(__dword_ptr[rbx + 8], eax); // eax = old claimSeq (zero-extends rax)
            a.and(eax, mask);                         // slot index
            a.imul(eax, eax, recordSize);             // byte offset (zero-extends rax)

            a.mov(rdi, bufferAddress);
            a.add(rdi, rax);                          // rdi = &slot

            a.rdtsc();                                // edx:eax (upper halves cleared)
            a.mov(__dword_ptr[rdi + 0], eax);
            a.mov(__dword_ptr[rdi + 4], edx);

            a.mov(rax, __qword_ptr[rsp + 64]);        // source = return address
            a.mov(__qword_ptr[rdi + 8], rax);

            a.mov(rax, destination);                  // destination (imm64)
            a.mov(__qword_ptr[rdi + 16], rax);

            a.lea(rax, __[rsp + 64]);                  // stack pointer at entry
            a.mov(__qword_ptr[rdi + 24], rax);

            a.mov(__dword_ptr[rdi + 32], argCount);

            // First four args from the saved register slots, then stack args.
            int[] regSlots = { 40, 32, 24, 16 }; // saved rcx, rdx, r8, r9
            for (int i = 0; i < argCount; i++)
            {
                if (i < 4)
                    a.mov(rax, __qword_ptr[rsp + regSlots[i]]);
                else
                    a.mov(rax, __qword_ptr[rsp + 104 + (i - 4) * 8]);
                a.mov(__qword_ptr[rdi + 36 + i * 8], rax);
            }

            // stack snapshot: copy StackSlots words from the entry stack upward.
            // rbx/rdx/rcx/rax are all saved and restored by the pops below; rdi
            // (the record base) is kept for the derefCount write after the loop.
            a.mov(__dword_ptr[rdi + stackCountOff], StackSlots);
            a.lea(rbx, __[rsp + 64]);                 // source = entry rsp
            a.lea(rdx, __[rdi + snapshotOff]);        // dest = snapshot region
            a.mov(ecx, StackSlots);
            var copy = a.CreateLabel();
            a.Label(ref copy);
            a.mov(rax, __qword_ptr[rbx]);
            a.mov(__qword_ptr[rdx], rax);
            a.add(rbx, 8);
            a.add(rdx, 8);
            a.dec(ecx);
            a.jnz(copy);

            a.mov(__dword_ptr[rdi + derefCountOff], 0); // derefCount = 0

            a.popfq();
            a.pop(rdi);
            a.pop(r9);
            a.pop(r8);
            a.pop(rdx);
            a.pop(rcx);
            a.pop(rbx);
            a.pop(rax);
            // (chain to trampoline is appended below as a RIP-relative indirect jmp)

            var writer = new Cda.Core.Cpu.ListCodeWriter();
            a.Assemble(writer, stubAddress);

            var bytes = new List<byte>(writer.Bytes);
            // jmp qword ptr [rip+0] ; dq trampolineAddress
            bytes.Add(0xFF); bytes.Add(0x25);
            bytes.Add(0x00); bytes.Add(0x00); bytes.Add(0x00); bytes.Add(0x00);
            for (int i = 0; i < 8; i++) bytes.Add((byte)(trampolineAddress >> (i * 8)));
            return bytes.ToArray();
        }
    }
}
