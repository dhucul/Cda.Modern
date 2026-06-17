using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Iced.Intel;
using Cda.Core.Cpu;

namespace Cda.Core.Engine
{
    /// <summary>
    /// An inline (entry-point) detour. <see cref="Trampoline"/> is the address to
    /// call to reach the original function (relocated stolen instructions + a jump
    /// back past the patch).
    ///
    /// Installation is two-phase so callers can avoid a race: <see cref="Install"/>
    /// with <c>activate: false</c> builds the trampoline and the patch but leaves
    /// the entry untouched, so the caller can populate the detour body (the capture
    /// stub) first; <see cref="Activate"/> then writes the entry patch as the final
    /// step, when everything it points at is already in place.
    /// </summary>
    public sealed class InlineHook
    {
        public ulong Target { get; }
        public ulong Detour { get; }
        public ulong Trampoline { get; }
        public int PatchLength { get; }
        public bool IsActive => _activated && !_removed;

        private readonly ICodeMemory _mem;
        private readonly byte[] _original;
        private readonly byte[] _patch;
        private bool _activated;
        private bool _removed;

        internal InlineHook(ICodeMemory mem, ulong target, ulong detour, ulong trampoline,
            int patchLen, byte[] original, byte[] patch)
        {
            _mem = mem;
            Target = target;
            Detour = detour;
            Trampoline = trampoline;
            PatchLength = patchLen;
            _original = original;
            _patch = patch;
        }

        public static InlineHook Install(ICpuArchitecture arch, ICodeMemory mem,
            ulong target, ulong detour, bool activate = true, int maxPatchLen = int.MaxValue)
        {
            if (!TryInstall(arch, mem, target, detour, activate, out var hook, out string? reason, maxPatchLen))
                throw new InvalidOperationException(reason ?? "Could not install hook.");
            return hook!;
        }

        /// <summary>
        /// Non-throwing install. Returns false (with a human-readable
        /// <paramref name="skipReason"/>) for the routine, expected reasons a real
        /// function can't be safely spliced — an undecodable patch site, a branch
        /// into the patch region, or a trampoline that can't be relocated. These are
        /// normal outcomes when arming a broad candidate set, so they are reported
        /// rather than thrown: throwing for them floods a debugger's first-chance
        /// exception output on every capture start. Genuinely unexpected failures
        /// (e.g. a failed cross-process write) still throw.
        /// </summary>
        public static bool TryInstall(ICpuArchitecture arch, ICodeMemory mem,
            ulong target, ulong detour, bool activate, out InlineHook? hook, out string? skipReason,
            int maxPatchLen = int.MaxValue)
        {
            hook = null;
            skipReason = null;
            int bitness = arch.Is64Bit ? 64 : 32;

            byte[] window = new byte[32];
            mem.Read(target, window);

            // Reserve exactly what the entry jump needs: 5 bytes for an in-range
            // E9, or 14 for the x64 absolute indirect jump. Knowing the detour
            // address now avoids over-stealing 14 bytes from small functions when
            // 5 will do (which would otherwise overrun into the next function).
            byte[] detourJmp = BuildJump(target, detour, arch.Is64Bit);
            int minPatch = detourJmp.Length;

            int patchLen = Disasm.HookLengthBytes(bitness, window, minPatch);
            if (patchLen == 0)
            {
                skipReason = "Could not decode a clean patch site at the target.";
                return false;
            }

            // Refuse to steal past the function's known extent (the caller passes
            // the .pdata-derived size, or the gap to the next entry). A 5-byte E9
            // over a tiny function would otherwise overwrite the start of the next
            // function, which then crashes when it is called directly.
            if (patchLen > maxPatchLen)
            {
                skipReason = $"Patch ({patchLen} B) would overrun the function extent ({maxPatchLen} B) into the next function.";
                return false;
            }

            byte[] original = new byte[patchLen];
            Array.Copy(window, original, patchLen);

            // Refuse the site if any instruction in the function's opening window
            // branches INTO the bytes we're about to overwrite. A loop/branch back
            // into the patch would land in the middle of our jump and crash the
            // target. This is the most common splice hazard for real functions.
            if (BranchesIntoPatch(bitness, mem, target, patchLen))
            {
                skipReason = "A branch targets the patch region; unsafe to hook.";
                return false;
            }

            // Trampoline = relocated stolen instructions + a jump back past the
            // patch, allocated WITHIN +/-2GB of the target so its stolen
            // RIP-relative operands relocate in rel32 range (a far trampoline is
            // exactly what makes them "too far" to relocate, skipping the site).
            // The jump-back is appended to the instruction list and encoded
            // AS PART OF the block — NOT glued on after BlockEncoder runs. Here's why
            // that matters: when a stolen instruction is a relative branch whose
            // target is out of rel32 reach of the (often far-allocated) trampoline,
            // BlockEncoder rewrites it into "j<ncc> skip ; jmp [rip] <abs>" and parks
            // the 8-byte <abs> in a data table at the END of the block. A jump-back
            // appended after that table sits past it, so the NOT-TAKEN fall-through
            // of such a rewritten branch lands on the inter-block alignment padding
            // (int3, 0xCC) before the table instead of reaching the jump-back — an
            // unhandled int3 that kills the target (and only on functions whose
            // stolen prologue contains a branch, i.e. "some programs, not all").
            // Making the jump-back the block's final instruction puts it right after
            // the code, so every fall-through reaches it, and BlockEncoder fixes up
            // its reach the same way (rel32, or its own jmp [rip] entry when the
            // resumed body is itself out of rel32 range of the trampoline).
            ulong trampoline = mem.AllocateNear(patchLen * 2 + 64, target);
            var stolen = Disasm.DecodeRange(bitness, original, target, patchLen);
            stolen.Add(Instruction.CreateBranch(
                arch.Is64Bit ? Code.Jmp_rel32_64 : Code.Jmp_rel32_32, target + (ulong)patchLen));

            var writer = new ListCodeWriter();
            var block = new InstructionBlock(writer, stolen, trampoline);
            if (!BlockEncoder.TryEncode(bitness, block, out string? error, out _))
            {
                skipReason = "Trampoline relocation failed: " + error;
                return false;
            }
            byte[] trampBytes = writer.Bytes.ToArray();
            mem.Write(trampoline, trampBytes);
            mem.Flush(trampoline, trampBytes.Length);

            // Build (but do not yet apply) the entry patch using the jump computed above.
            byte[] patch = new byte[patchLen];
            Array.Copy(detourJmp, patch, detourJmp.Length);
            for (int i = detourJmp.Length; i < patchLen; i++) patch[i] = 0x90; // nop

            hook = new InlineHook(mem, target, detour, trampoline, patchLen, original, patch);
            if (activate) hook.Activate();
            return true;
        }

        /// <summary>Write the entry patch — the final step that arms the detour.</summary>
        public void Activate()
        {
            if (_activated || _removed) return;
            uint old = _mem.Protect(Target, PatchLength, Process.NativeMethods.PAGE_EXECUTE_READWRITE);
            _mem.Write(Target, _patch);
            _mem.Protect(Target, PatchLength, old);
            _mem.Flush(Target, PatchLength);
            _activated = true;
        }

        /// <summary>
        /// True if <paramref name="addr"/> falls inside this hook's footprint — the
        /// patched entry bytes, the detour body (capture stub), or the relocated
        /// trampoline. Lets a live fault be blamed on the hook whose generated code it
        /// landed in. <paramref name="stubSize"/> is the byte budget the caller wrote
        /// the stub into (the trampoline's own size is known here).
        /// </summary>
        public bool OwnsAddress(ulong addr, int stubSize)
        {
            if (addr >= Target && addr < Target + (ulong)PatchLength) return true;
            if (addr >= Detour && addr < Detour + (ulong)stubSize) return true;
            int trampSize = PatchLength * 2 + 64; // matches the AllocateNear size in TryInstall
            if (addr >= Trampoline && addr < Trampoline + (ulong)trampSize) return true;
            return false;
        }

        /// <summary>Restore the original entry bytes.</summary>
        public void Remove()
        {
            if (_removed) return;
            if (!_activated) { _removed = true; return; }
            uint old = _mem.Protect(Target, PatchLength, Process.NativeMethods.PAGE_EXECUTE_READWRITE);
            _mem.Write(Target, _original);
            _mem.Protect(Target, PatchLength, old);
            _mem.Flush(Target, PatchLength);
            _removed = true;
        }

        /// <summary>
        /// True if any instruction in the function's opening window has a near
        /// branch whose target lands strictly inside (target, target+patchLen) —
        /// i.e. into the bytes the entry patch will overwrite. The scan is bounded
        /// and stops at the first return.
        /// </summary>
        private static bool BranchesIntoPatch(int bitness, ICodeMemory mem, ulong target, int patchLen)
        {
            byte[] code = new byte[1024];
            int read = mem.Read(target, code);
            if (read <= 0) return false;

            var reader = new ByteArrayCodeReader(code, 0, read);
            var decoder = Decoder.Create(bitness, reader, target, DecoderOptions.None);
            ulong lo = target;
            ulong hi = target + (ulong)patchLen;

            while (reader.CanReadByte)
            {
                decoder.Decode(out Instruction instr);
                if (instr.Code == Code.INVALID) break;

                if (instr.Op0Kind == OpKind.NearBranch16 ||
                    instr.Op0Kind == OpKind.NearBranch32 ||
                    instr.Op0Kind == OpKind.NearBranch64)
                {
                    ulong t = instr.NearBranchTarget;
                    if (t > lo && t < hi) return true;
                }

                if (instr.FlowControl == FlowControl.Return) break; // bound to this function
            }
            return false;
        }

        /// <summary>
        /// 5-byte E9 rel32 when in range, else a 14-byte RIP-relative indirect
        /// jump (FF 25 + absolute 64-bit pointer) for far x64 targets.
        /// </summary>
        private static byte[] BuildJump(ulong from, ulong to, bool is64)
        {
            long rel = (long)to - (long)(from + 5);
            if (!is64 || (rel >= int.MinValue && rel <= int.MaxValue))
            {
                var b = new byte[5];
                b[0] = 0xE9;
                BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(1), (int)rel);
                return b;
            }

            var far = new byte[14];
            far[0] = 0xFF;
            far[1] = 0x25;
            BinaryPrimitives.WriteUInt32LittleEndian(far.AsSpan(2), 0);
            BinaryPrimitives.WriteUInt64LittleEndian(far.AsSpan(6), to);
            return far;
        }
    }
}
