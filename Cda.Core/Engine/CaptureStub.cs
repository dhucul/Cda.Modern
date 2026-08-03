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
    ///   * a correlation id (the claim sequence) so a call can be paired with the
    ///     record written when it returns (return-value capture),
    ///   * a fixed-depth snapshot of the stack from the entry SP upward, so the
    ///     host can walk past runtime/CRT wrappers back to the program's own code,
    ///   * claims its slot with <c>lock xadd</c> so concurrent threads are safe.
    ///
    /// <b>Return-value capture (opt-in).</b> When a return stub + a per-hook return
    /// context are supplied, the entry stub also tries to atomically claim the
    /// hook's single return slot (<c>lock cmpxchg</c>). If it wins, it stashes the
    /// real return address + correlation id in the context and overwrites the
    /// on-stack return address so the callee returns into the shared return stub,
    /// which records the return value (RAX/EAX) and resumes at the real caller. If
    /// it loses (a concurrent or recursive call already owns the slot), it does not
    /// redirect — so at most one outstanding return per hooked function is tracked
    /// at a time, and an exception/tail-call that never returns simply leaves the
    /// slot owned (return capture quietly stops for that hook) rather than ever
    /// jumping to a stale address. This needs no per-thread (TLS) state, so it is
    /// expressible with the fluent assembler.
    ///
    /// <b>x64 exception safety.</b> While a call's return is redirected, its on-stack
    /// return address points at the return stub, which carries no <c>.pdata</c> unwind
    /// info — so a C++/SEH exception unwinding through that live frame would make the
    /// x64 table-based unwinder mis-unwind and crash. This is handled by a first-chance
    /// <b>vectored exception handler</b> installed in the target
    /// (<see cref="BuildReturnVehX64"/>): before any unwind, it restores every
    /// outstanding redirected return address at/above the fault SP to its real value, so
    /// the unwinder sees the correct address. Restoring a slot only un-redirects that one
    /// call (no crash), so it is always safe. If the handler cannot be installed,
    /// x64 capture stays in entry-only mode; it never redirects a return without
    /// this safety net. (x86's chain-based SEH is unaffected and needs no handler.)
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
        /// stacks; RecordSize(4) is then 600 bytes, so a 65,536-slot ring is ~39 MB
        /// in the target. Raising this deepens both at a linear memory cost; because
        /// it changes the record format, re-run the capture Self-test after changing
        /// it.
        /// </summary>
        public const int StackSlots = 64;

        /// <summary>Set in the record's argCount field to mark a return record (paired
        /// to its call by correlation id). The real argument count is the low bits.</summary>
        public const uint KindReturn = 0x8000_0000u;

        // Fixed field offsets shared by the entry stub, the return stub, and the
        // host decoder. Args start at 40 (after an 8-word header + the u32 argCount
        // + the u32 correlation id).
        private const int OffTimestamp = 0;
        private const int OffSource = 8;
        private const int OffDestination = 16;
        private const int OffStackPointer = 24;
        private const int OffArgCount = 32;
        private const int OffCorrelation = 36;
        private const int OffArgs = 40;
        internal const int CommitBytes = 8;

        /// <summary>Per-hook return context laid out in target memory (zero-initialised).</summary>
        internal const int CtxBusy = 0;     // u32: 0 free, 2 claimed, 1 armed
        internal const int CtxOrigRet = 8;  // pointer-sized: real return address
        internal const int CtxCorrId = 16;  // u32: the owning call's correlation id
        internal const int CtxSlotAddr = 24;// pointer-sized: stack address of the overwritten return slot
        internal const int ReturnContextSize = 32;

        /// <summary>Bytes a record occupies for the given fixed argument count.</summary>
        public static int RecordSize(int argCount)
            => OffArgs             // timestamp + source + destination + stackPointer + argCount + correlationId
             + argCount * 8        // integer args
             + 4                   // stackSlots count
             + StackSlots * 8      // stack snapshot
             + 4                   // derefCount
             + CommitBytes;        // own claim sequence + bitwise complement, published last

        private static int CommitSequenceOffset(int argCount) => RecordSize(argCount) - CommitBytes;
        private static int CommitInverseOffset(int argCount) => RecordSize(argCount) - sizeof(uint);

        /// <summary>
        /// Build the stub for the address it will be written to. Absolute target
        /// addresses are embedded as immediates, so the stub is specific to this
        /// allocation. Pass a non-zero <paramref name="returnStubAddress"/> and
        /// <paramref name="returnCtxAddress"/> to enable return-value capture.
        /// </summary>
        public static byte[] BuildX86(
            ulong stubAddress, ulong destination, ulong controlAddress,
            ulong bufferAddress, ulong trampolineAddress, int argCount, int slotCount,
            ulong returnStubAddress = 0, ulong returnCtxAddress = 0)
        {
            int recordSize = RecordSize(argCount);
            int mask = slotCount - 1; // slotCount is a power of two
            int ctrl = unchecked((int)(uint)controlAddress);
            int buf = unchecked((int)(uint)bufferAddress);
            int dst = unchecked((int)(uint)destination);

            int stackCountOff = OffArgs + argCount * 8;
            int snapshotOff = stackCountOff + 4;
            int derefCountOff = snapshotOff + StackSlots * 8;
            int commitSequenceOff = CommitSequenceOffset(argCount);
            int commitInverseOff = CommitInverseOffset(argCount);

            var a = new Assembler(32);

            // Preserve flags + all GP registers; the function must see its entry
            // state unchanged when we chain to the trampoline.
            a.pushfd();
            a.pushad(); // 32 bytes; with pushfd, original esp = esp + 36

            // Atomically claim a ring slot: eax = our sequence number (correlation
            // id), claimSeq++. index = seq & (slotCount-1); offset = index *
            // recordSize. slotCount is a power of two, so the offset is always in
            // range — no bounds check.
            a.mov(eax, 1);
            a.mov(ebx, ctrl);
            a.@lock.xadd(__dword_ptr[ebx + 8], eax); // eax = old claimSeq (correlation id)
            a.mov(ecx, eax);                          // keep the correlation id (rcx free until the snapshot loop)
            a.and(eax, mask);                         // slot index
            a.imul(eax, eax, recordSize);             // byte offset into the ring

            a.mov(edi, buf);
            a.add(edi, eax);                   // edi = &slot
            // Invalidate the previous occupant before touching its payload. The host
            // accepts a slot only when commitSeq == seq and commitInv == ~seq.
            a.mov(__dword_ptr[edi + commitInverseOff], ecx);

            // timestamp (edx:eax)
            a.rdtsc();
            a.mov(__dword_ptr[edi + OffTimestamp], eax);
            a.mov(__dword_ptr[edi + OffTimestamp + 4], edx);

            // source = return address at [esp+36]
            a.mov(eax, __dword_ptr[esp + 36]);
            a.mov(__dword_ptr[edi + OffSource], eax);
            a.mov(__dword_ptr[edi + OffSource + 4], 0);

            // destination (constant)
            a.mov(__dword_ptr[edi + OffDestination], dst);
            a.mov(__dword_ptr[edi + OffDestination + 4], 0);

            // stack pointer at entry = esp + 36
            a.lea(eax, __[esp + 36]);
            a.mov(__dword_ptr[edi + OffStackPointer], eax);
            a.mov(__dword_ptr[edi + OffStackPointer + 4], 0);

            // argCount (kind = call: high bit clear) and correlation id
            a.mov(__dword_ptr[edi + OffArgCount], argCount);
            a.mov(__dword_ptr[edi + OffCorrelation], ecx);

            // NT_TIB.StackBase bounds every read above the entry SP. A hook can run
            // with ESP close to the top of the final committed stack page, and an
            // unconditional fixed-depth read there would fault inside the target.
            a.mov(ebp, __dword_ptr.fs[4]);

            // stack args: arg_i at [esp + 40 + i*4]; stored as u64 (hi = 0).
            // A function may have fewer arguments than our generic capture width,
            // so zero-fill an argument whose word would reach StackBase.
            for (int i = 0; i < argCount; i++)
            {
                var unavailable = a.CreateLabel();
                var stored = a.CreateLabel();
                a.lea(esi, __[esp + 40 + i * 4]);
                a.cmp(esi, ebp);
                a.jae(unavailable);
                a.mov(eax, __dword_ptr[esp + 40 + i * 4]);
                a.jmp(stored);
                a.Label(ref unavailable);
                a.xor(eax, eax);
                a.Label(ref stored);
                a.mov(__dword_ptr[edi + OffArgs + i * 8], eax);
                a.mov(__dword_ptr[edi + OffArgs + i * 8 + 4], 0);
            }

            // Stack snapshot: copy only the words that fit below StackBase.
            // esi/edx/eax/ecx are all preserved by pushad; edi (the record base)
            // is kept for the derefCount write and the redirect after the loop.
            a.lea(esi, __[esp + 36]);              // source = entry esp
            a.cmp(ebp, esi);
            var noStack = a.CreateLabel();
            var countReady = a.CreateLabel();
            var copyDone = a.CreateLabel();
            a.jbe(noStack);
            a.sub(ebp, esi);
            a.shr(ebp, 2);
            a.cmp(ebp, StackSlots);
            a.jbe(countReady);
            a.mov(ebp, StackSlots);
            a.Label(ref countReady);
            a.mov(__dword_ptr[edi + stackCountOff], ebp);
            a.lea(edx, __[edi + snapshotOff]);     // dest = snapshot region
            a.mov(ecx, ebp);
            a.test(ecx, ecx);
            a.jz(copyDone);
            var copy = a.CreateLabel();
            a.Label(ref copy);
            a.mov(eax, __dword_ptr[esi]);
            a.mov(__dword_ptr[edx + 0], eax);
            a.mov(__dword_ptr[edx + 4], 0);        // zero-extend to 64-bit
            a.add(esi, 4);
            a.add(edx, 8);
            a.dec(ecx);
            a.jnz(copy);
            a.jmp(copyDone);
            a.Label(ref noStack);
            a.mov(__dword_ptr[edi + stackCountOff], 0);
            a.Label(ref copyDone);

            // derefCount = 0 (no in-target pointer-following in this version)
            a.mov(__dword_ptr[edi + derefCountOff], 0);

            // Publish the slot only after every payload field is complete.
            a.mov(eax, __dword_ptr[edi + OffCorrelation]);
            a.mov(__dword_ptr[edi + commitSequenceOff], eax);
            a.not(eax);
            a.mov(__dword_ptr[edi + commitInverseOff], eax);

            // --- optional return redirect: claim the hook's single return slot ---
            if (returnStubAddress != 0 && returnCtxAddress != 0)
            {
                int ctx = unchecked((int)(uint)returnCtxAddress);
                var skip = a.CreateLabel();
                a.mov(ebx, ctx);
                a.xor(eax, eax);                             // expected busy = 0
                a.mov(edx, 1);                               // desired busy = 1
                a.@lock.cmpxchg(__dword_ptr[ebx + CtxBusy], edx); // ZF=1 if we acquired
                a.jnz(skip);                                 // busy → do not redirect
                a.mov(eax, __dword_ptr[esp + 36]);           // original return address
                a.mov(__dword_ptr[ebx + CtxOrigRet], eax);
                a.mov(__dword_ptr[ebx + CtxOrigRet + 4], 0);
                a.mov(eax, __dword_ptr[edi + OffCorrelation]); // correlation id
                a.mov(__dword_ptr[ebx + CtxCorrId], eax);
                a.lea(eax, __[esp + 36]);                    // address of the return slot (for the VEH fixup)
                a.mov(__dword_ptr[ebx + CtxSlotAddr], eax);
                a.mov(__dword_ptr[ebx + CtxSlotAddr + 4], 0);
                a.mov(__dword_ptr[esp + 36], unchecked((int)(uint)returnStubAddress)); // redirect the return
                a.Label(ref skip);
            }

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
            ulong bufferAddress, ulong trampolineAddress, int argCount, int slotCount,
            ulong returnStubAddress = 0, ulong returnCtxAddress = 0)
            => is64Bit
                ? BuildX64(stubAddress, destination, controlAddress, bufferAddress, trampolineAddress, argCount, slotCount, returnStubAddress, returnCtxAddress)
                : BuildX86(stubAddress, destination, controlAddress, bufferAddress, trampolineAddress, argCount, slotCount, returnStubAddress, returnCtxAddress);

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
            ulong bufferAddress, ulong trampolineAddress, int argCount, int slotCount,
            ulong returnStubAddress = 0, ulong returnCtxAddress = 0)
        {
            int recordSize = RecordSize(argCount);
            int mask = slotCount - 1; // slotCount is a power of two

            int stackCountOff = OffArgs + argCount * 8;
            int snapshotOff = stackCountOff + 4;
            int derefCountOff = snapshotOff + StackSlots * 8;
            int commitSequenceOff = CommitSequenceOffset(argCount);
            int commitInverseOff = CommitInverseOffset(argCount);

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
            a.@lock.xadd(__dword_ptr[rbx + 8], eax); // eax = old claimSeq (correlation id; zero-extends rax)
            a.mov(ecx, eax);                          // keep the correlation id (rcx free until the snapshot loop)
            a.mov(r10d, eax);                         // keep our own claim sequence through the copy loop
            a.and(eax, mask);                         // slot index
            a.imul(eax, eax, recordSize);             // byte offset (zero-extends rax)

            a.mov(rdi, bufferAddress);
            a.add(rdi, rax);                          // rdi = &slot
            a.mov(__dword_ptr[rdi + commitInverseOff], r10d); // invalidate previous occupant

            a.rdtsc();                                // edx:eax (upper halves cleared)
            a.mov(__dword_ptr[rdi + OffTimestamp], eax);
            a.mov(__dword_ptr[rdi + OffTimestamp + 4], edx);

            a.mov(rax, __qword_ptr[rsp + 64]);        // source = return address
            a.mov(__qword_ptr[rdi + OffSource], rax);

            a.mov(rax, destination);                  // destination (imm64)
            a.mov(__qword_ptr[rdi + OffDestination], rax);

            a.lea(rax, __[rsp + 64]);                  // stack pointer at entry
            a.mov(__qword_ptr[rdi + OffStackPointer], rax);

            a.mov(__dword_ptr[rdi + OffArgCount], argCount); // kind = call (high bit clear)
            a.mov(__dword_ptr[rdi + OffCorrelation], ecx);   // correlation id

            // NT_TIB.StackBase is at gs:[8] in a native x64 thread. It bounds
            // both optional stack arguments and the snapshot copy below.
            a.mov(r11, __qword_ptr.gs[8]);

            // First four args from the saved register slots, then stack args.
            int[] regSlots = { 40, 32, 24, 16 }; // saved rcx, rdx, r8, r9
            for (int i = 0; i < argCount; i++)
            {
                if (i < 4)
                    a.mov(rax, __qword_ptr[rsp + regSlots[i]]);
                else
                {
                    var unavailable = a.CreateLabel();
                    var stored = a.CreateLabel();
                    a.lea(rbx, __[rsp + 104 + (i - 4) * 8]);
                    a.cmp(rbx, r11);
                    a.jae(unavailable);
                    a.mov(rax, __qword_ptr[rsp + 104 + (i - 4) * 8]);
                    a.jmp(stored);
                    a.Label(ref unavailable);
                    a.xor(eax, eax);
                    a.Label(ref stored);
                }
                a.mov(__qword_ptr[rdi + OffArgs + i * 8], rax);
            }

            // Stack snapshot: copy only the words below StackBase.
            // rbx/rdx/rcx/rax are all saved and restored by the pops below; rdi
            // (the record base) is kept for the derefCount write and the redirect.
            a.lea(rbx, __[rsp + 64]);                 // source = entry rsp
            a.cmp(r11, rbx);
            var noStack = a.CreateLabel();
            var countReady = a.CreateLabel();
            var copyDone = a.CreateLabel();
            a.jbe(noStack);
            a.sub(r11, rbx);
            a.shr(r11, 3);
            a.cmp(r11, StackSlots);
            a.jbe(countReady);
            a.mov(r11, StackSlots);
            a.Label(ref countReady);
            a.mov(__dword_ptr[rdi + stackCountOff], r11d);
            a.lea(rdx, __[rdi + snapshotOff]);        // dest = snapshot region
            a.mov(ecx, r11d);
            a.test(ecx, ecx);
            a.jz(copyDone);
            var copy = a.CreateLabel();
            a.Label(ref copy);
            a.mov(rax, __qword_ptr[rbx]);
            a.mov(__qword_ptr[rdx], rax);
            a.add(rbx, 8);
            a.add(rdx, 8);
            a.dec(ecx);
            a.jnz(copy);
            a.jmp(copyDone);
            a.Label(ref noStack);
            a.mov(__dword_ptr[rdi + stackCountOff], 0);
            a.Label(ref copyDone);

            a.mov(__dword_ptr[rdi + derefCountOff], 0); // derefCount = 0

            // Publish the slot only after every payload field is complete.
            a.mov(__dword_ptr[rdi + commitSequenceOff], r10d);
            a.not(r10d);
            a.mov(__dword_ptr[rdi + commitInverseOff], r10d);

            // --- optional return redirect: claim the hook's single return slot ---
            if (returnStubAddress != 0 && returnCtxAddress != 0)
            {
                var skip = a.CreateLabel();
                a.mov(rbx, returnCtxAddress);
                a.xor(eax, eax);                                  // expected busy = 0
                a.mov(edx, 2);                                    // claimed, not yet armed
                a.@lock.cmpxchg(__dword_ptr[rbx + CtxBusy], edx); // ZF=1 if acquired
                a.jnz(skip);                                      // busy → do not redirect
                a.mov(rax, __qword_ptr[rsp + 64]);                // original return address
                a.mov(__qword_ptr[rbx + CtxOrigRet], rax);
                a.mov(eax, __dword_ptr[rdi + OffCorrelation]);    // correlation id
                a.mov(__dword_ptr[rbx + CtxCorrId], eax);
                a.lea(rax, __[rsp + 64]);                         // address of the return slot (for the VEH fixup)
                a.mov(__qword_ptr[rbx + CtxSlotAddr], rax);
                a.mov(__dword_ptr[rbx + CtxBusy], 1);             // publish only after the context is complete
                a.mov(rax, returnStubAddress);
                a.mov(__qword_ptr[rsp + 64], rax);                // redirect the return
                a.Label(ref skip);
            }

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

        /// <summary>Build the shared return stub for a hook (the address the callee
        /// returns into after redirection). Records the return value (RAX/EAX) as a
        /// return record paired to its call by correlation id, releases the hook's
        /// return slot, and resumes at the real caller.</summary>
        public static byte[] BuildReturnStub(
            bool is64Bit, ulong stubAddress, ulong destination, ulong controlAddress,
            ulong bufferAddress, int argCount, int slotCount, ulong returnCtxAddress)
            => is64Bit
                ? BuildReturnStubX64(stubAddress, destination, controlAddress, bufferAddress, argCount, slotCount, returnCtxAddress)
                : BuildReturnStubX86(stubAddress, destination, controlAddress, bufferAddress, argCount, slotCount, returnCtxAddress);

        private static byte[] BuildReturnStubX64(
            ulong stubAddress, ulong destination, ulong controlAddress,
            ulong bufferAddress, int argCount, int slotCount, ulong returnCtxAddress)
        {
            int recordSize = RecordSize(argCount);
            int mask = slotCount - 1;
            int stackCountOff = OffArgs + argCount * 8;
            int derefCountOff = stackCountOff + 4 + StackSlots * 8;
            int commitSequenceOff = CommitSequenceOffset(argCount);
            int commitInverseOff = CommitInverseOffset(argCount);
            int kindArg = unchecked((int)(KindReturn | (uint)argCount));

            var a = new Assembler(64);

            // The callee has returned; the integer return value is in RAX (RDX may
            // carry the high half of a 128-bit return). RBX/RDI are non-volatile —
            // the caller relies on them — so preserve everything we touch. r11 is
            // volatile and used as the resume-address scratch (survives the pops).
            a.push(rax);   // [rsp+40] return value
            a.push(rbx);   // [rsp+32]
            a.push(rcx);   // [rsp+24]
            a.push(rdx);   // [rsp+16]
            a.push(rdi);   // [rsp+8]
            a.pushfq();    // [rsp+0]

            a.mov(rbx, controlAddress);
            a.mov(eax, 1);
            a.@lock.xadd(__dword_ptr[rbx + 8], eax);
            a.mov(ecx, eax);                           // this return record's own claim sequence
            a.and(eax, mask);
            a.imul(eax, eax, recordSize);
            a.mov(rdi, bufferAddress);
            a.add(rdi, rax);                          // rdi = &slot
            a.mov(__dword_ptr[rdi + commitInverseOff], ecx); // invalidate previous occupant

            a.rdtsc();
            a.mov(__dword_ptr[rdi + OffTimestamp], eax);
            a.mov(__dword_ptr[rdi + OffTimestamp + 4], edx);

            a.mov(rbx, returnCtxAddress);
            a.mov(rax, __qword_ptr[rbx + CtxOrigRet]); // source = where it returns to
            a.mov(__qword_ptr[rdi + OffSource], rax);
            a.mov(rax, destination);                   // destination = the callee that returned
            a.mov(__qword_ptr[rdi + OffDestination], rax);
            a.xor(eax, eax);
            a.mov(__qword_ptr[rdi + OffStackPointer], rax); // stack pointer n/a
            a.mov(__dword_ptr[rdi + OffArgCount], kindArg);  // kind = return
            a.mov(eax, __dword_ptr[rbx + CtxCorrId]);
            a.mov(__dword_ptr[rdi + OffCorrelation], eax);

            a.mov(rax, __qword_ptr[rsp + 40]);         // the saved return value
            a.mov(__qword_ptr[rdi + OffArgs], rax);    // args[0] = return value
            for (int i = 1; i < argCount; i++)
                a.mov(__qword_ptr[rdi + OffArgs + i * 8], 0);

            a.mov(__dword_ptr[rdi + stackCountOff], 0);          // return records carry no snapshot
            a.mov(__dword_ptr[rdi + derefCountOff], 0);

            a.mov(__dword_ptr[rdi + commitSequenceOff], ecx);
            a.not(ecx);
            a.mov(__dword_ptr[rdi + commitInverseOff], ecx);

            a.mov(r11, __qword_ptr[rbx + CtxOrigRet]); // grab the resume address (last read of ctx)
            a.mov(__dword_ptr[rbx + CtxBusy], 0);      // release the hook's return slot

            a.popfq();
            a.pop(rdi);
            a.pop(rdx);
            a.pop(rcx);
            a.pop(rbx);
            a.pop(rax);            // restore the return value
            a.jmp(r11);            // resume at the real caller

            var writer = new Cda.Core.Cpu.ListCodeWriter();
            a.Assemble(writer, stubAddress);
            return writer.Bytes.ToArray();
        }

        private static byte[] BuildReturnStubX86(
            ulong stubAddress, ulong destination, ulong controlAddress,
            ulong bufferAddress, int argCount, int slotCount, ulong returnCtxAddress)
        {
            int recordSize = RecordSize(argCount);
            int mask = slotCount - 1;
            int ctrl = unchecked((int)(uint)controlAddress);
            int buf = unchecked((int)(uint)bufferAddress);
            int dst = unchecked((int)(uint)destination);
            int ctx = unchecked((int)(uint)returnCtxAddress);
            int stackCountOff = OffArgs + argCount * 8;
            int derefCountOff = stackCountOff + 4 + StackSlots * 8;
            int commitSequenceOff = CommitSequenceOffset(argCount);
            int commitInverseOff = CommitInverseOffset(argCount);
            int kindArg = unchecked((int)(KindReturn | (uint)argCount));

            var a = new Assembler(32);

            // The callee has returned; the integer return value is in EAX. There is
            // no volatile register free to hold the resume address across the final
            // register restore, so reserve a stack slot and `ret` to it — copying
            // the resume address there before releasing the slot (race-free: only
            // one thread owns a hook's return stub at a time).
            a.sub(esp, 4);   // [entrySP-4] reserved for the resume address
            a.push(eax);     // [entrySP-8] return value
            a.push(ebx);     // [entrySP-12]
            a.push(ecx);     // [entrySP-16]
            a.push(edx);     // [entrySP-20]
            a.push(edi);     // [entrySP-24]
            a.pushfd();      // [entrySP-28]  (esp is now entrySP-28)

            a.mov(eax, 1);
            a.mov(ebx, ctrl);
            a.@lock.xadd(__dword_ptr[ebx + 8], eax);
            a.mov(ecx, eax);                           // this return record's own claim sequence
            a.and(eax, mask);
            a.imul(eax, eax, recordSize);
            a.mov(edi, buf);
            a.add(edi, eax);
            a.mov(__dword_ptr[edi + commitInverseOff], ecx); // invalidate previous occupant

            a.rdtsc();
            a.mov(__dword_ptr[edi + OffTimestamp], eax);
            a.mov(__dword_ptr[edi + OffTimestamp + 4], edx);

            a.mov(ebx, ctx);
            a.mov(eax, __dword_ptr[ebx + CtxOrigRet]);  // source = resume address
            a.mov(__dword_ptr[edi + OffSource], eax);
            a.mov(__dword_ptr[edi + OffSource + 4], 0);
            a.mov(__dword_ptr[edi + OffDestination], dst);
            a.mov(__dword_ptr[edi + OffDestination + 4], 0);
            a.mov(__dword_ptr[edi + OffStackPointer], 0);
            a.mov(__dword_ptr[edi + OffStackPointer + 4], 0);
            a.mov(__dword_ptr[edi + OffArgCount], kindArg);
            a.mov(eax, __dword_ptr[ebx + CtxCorrId]);
            a.mov(__dword_ptr[edi + OffCorrelation], eax);

            a.mov(eax, __dword_ptr[esp + 20]);          // the saved return value
            a.mov(__dword_ptr[edi + OffArgs], eax);     // args[0] = return value
            a.mov(__dword_ptr[edi + OffArgs + 4], 0);
            for (int i = 1; i < argCount; i++)
            {
                a.mov(__dword_ptr[edi + OffArgs + i * 8], 0);
                a.mov(__dword_ptr[edi + OffArgs + i * 8 + 4], 0);
            }

            a.mov(__dword_ptr[edi + stackCountOff], 0);
            a.mov(__dword_ptr[edi + derefCountOff], 0);

            a.mov(__dword_ptr[edi + commitSequenceOff], ecx);
            a.not(ecx);
            a.mov(__dword_ptr[edi + commitInverseOff], ecx);

            a.mov(eax, __dword_ptr[ebx + CtxOrigRet]);  // resume address
            a.mov(__dword_ptr[esp + 24], eax);          // store it in the reserved slot ([entrySP-4])
            a.mov(__dword_ptr[ebx + CtxBusy], 0);       // release the hook's return slot (resume already copied)

            a.popfd();
            a.pop(edi);
            a.pop(edx);
            a.pop(ecx);
            a.pop(ebx);
            a.pop(eax);      // restore the return value; esp now at [entrySP-4]
            a.ret();         // pop the reserved slot (resume address) into EIP; esp -> entrySP

            var writer = new Cda.Core.Cpu.ListCodeWriter();
            a.Assemble(writer, stubAddress);
            return writer.Bytes.ToArray();
        }

        /// <summary>
        /// Build the x64 first-chance vectored exception handler that makes return
        /// capture exception-safe. While a call's return is redirected, its on-stack
        /// return address points at the return stub, which has no <c>.pdata</c> unwind
        /// info — so a C++/SEH exception unwinding through that live frame would
        /// mis-unwind and crash. This handler, run first-chance on the faulting thread
        /// BEFORE any unwind, restores every outstanding redirected return address
        /// at/above the fault SP back to its original value (and releases the slot), so
        /// the unwinder sees the real return address. Restoring a slot is always benign
        /// — it just un-redirects that one call (no crash, no corruption) — so no
        /// per-thread stack-bounds check is needed, and touching another thread's slot
        /// (if within range) only costs that call its return value. It iterates the
        /// context registry (a <c>u64 count</c> followed by <c>count</c> u64 ctx
        /// addresses). Signature <c>LONG Veh(PEXCEPTION_POINTERS)</c> (rcx); returns 0
        /// (EXCEPTION_CONTINUE_SEARCH). Uses only volatile registers → leaf, no unwind
        /// info of its own. x64 only (x86 SEH is chain-based and unaffected).
        /// </summary>
        public static byte[] BuildReturnVehX64(ulong stubAddress, ulong registryAddress, int scanBytes)
        {
            var a = new Assembler(64);
            a.mov(rax, __qword_ptr[rcx + 8]);         // rcx = PEXCEPTION_POINTERS; rax = ContextRecord
            a.mov(r11, __qword_ptr[rax + 0x98]);      // r11 = fault Rsp (CONTEXT.Rsp)
            a.mov(r10, registryAddress);              // r10 = &registry
            a.mov(r9, __qword_ptr[r10]);              // r9 = count
            a.add(r10, 8);                            // r10 = &addr[0]
            var done = a.CreateLabel();
            var loop = a.CreateLabel();
            var next = a.CreateLabel();
            a.test(r9, r9);
            a.jz(done);
            a.Label(ref loop);
            a.mov(r8, __qword_ptr[r10]);              // r8 = ctx address
            a.cmp(__dword_ptr[r8 + CtxBusy], 1);
            a.jne(next);                              // not a fully armed redirect
            a.mov(rax, __qword_ptr[r8 + CtxSlotAddr]);// rax = slot address
            a.cmp(rax, r11);
            a.jb(next);                               // below the fault SP → skip
            a.mov(rdx, r11);
            a.add(rdx, scanBytes);
            a.cmp(rax, rdx);
            a.jae(next);                              // too far above → skip
            a.mov(rdx, __qword_ptr[r8 + CtxOrigRet]); // original return address
            a.mov(__qword_ptr[rax], rdx);             // restore the return slot
            a.mov(__dword_ptr[r8 + CtxBusy], 0);      // release it
            a.Label(ref next);
            a.add(r10, 8);
            a.dec(r9);
            a.jnz(loop);
            a.Label(ref done);
            a.xor(eax, eax);                          // EXCEPTION_CONTINUE_SEARCH
            a.ret();

            var writer = new Cda.Core.Cpu.ListCodeWriter();
            a.Assemble(writer, stubAddress);
            return writer.Bytes.ToArray();
        }

        /// <summary>
        /// Build a one-shot x64 bootstrap that calls
        /// <c>AddVectoredExceptionHandler(1, veh)</c> and returns — run once in the
        /// target via a remote thread to register <see cref="BuildReturnVehX64"/>.
        /// </summary>
        public static byte[] BuildVehBootstrapX64(ulong stubAddress, ulong vehAddress, ulong addVehAddress)
        {
            var a = new Assembler(64);
            a.sub(rsp, 0x28);           // 16-align + 32-byte shadow space for the call
            a.mov(ecx, 1);              // First = 1 (run our handler first)
            a.mov(rdx, vehAddress);     // Handler
            a.mov(rax, addVehAddress);  // AddVectoredExceptionHandler
            a.call(rax);
            a.add(rsp, 0x28);
            a.test(rax, rax);
            a.setne(al);
            a.movzx(eax, al);           // thread exit code: 1 only when registration succeeded
            a.ret();

            var writer = new Cda.Core.Cpu.ListCodeWriter();
            a.Assemble(writer, stubAddress);
            return writer.Bytes.ToArray();
        }
    }
}
