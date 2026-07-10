using System;
using System.Collections.Generic;
using Iced.Intel;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Given a captured dialog call's return address and its pre-resolved
    /// caller chain, finds the exact conditional branch that controls whether
    /// the dialog fires — the "je / jne that jumps or not-jumps to the message
    /// box".
    ///
    /// The analyzer scans the immediate return site first (rec.Source), then
    /// walks the caller chain upward through each app-code frame, scanning
    /// each for a conditional branch whose target jumps past the call that
    /// reached the dialog. This handles:
    ///
    ///   (a) branch directly above the call (frame 0):
    ///         jne skip
    ///         call MessageBoxW   ← rec.Source = &skip
    ///         skip:
    ///
    ///   (b) branch one level up through a wrapper (frame 1):
    ///         jne skip          ← found in frame-1 caller
    ///         call ShowError
    ///         skip:
    ///         ShowError:
    ///            … setup …
    ///            call MessageBoxW  ← rec.Source inside ShowError
    ///
    ///   (c) custom dialog box via explicit CreateWindowEx (frame N):
    ///         jne skip          ← found in frame-N caller
    ///         call app!OpenMyDialog
    ///         skip:
    ///         app!OpenMyDialog:
    ///            … setup …
    ///            call user32!CreateWindowEx  ← rec.Source
    ///
    /// Each frame reads up to 512 instruction-bytes from the target's live
    /// code through a supplied reader delegate (host-side ReadProcessMemory —
    /// safe, read-only). Dialogs are infrequent, so the cost is negligible.
    /// </summary>
    public static class DialogBranchAnalyzer
    {
        /// <summary>Info about the conditional branch that gates a dialog-call path.</summary>
        public sealed class BranchInfo
        {
            /// <summary>Virtual address of the conditional-jump instruction.</summary>
            public ulong Address;

            /// <summary>Iced <see cref="Code"/> enum value for the branch (e.g. <c>Code.Jne_rel32_64</c>).</summary>
            public Code OpCode;

            /// <summary>Formatted mnemonic + target (e.g. "jne 0x140001250").</summary>
            public string Disassembly = "";

            /// <summary>The branch target (where it jumps to).</summary>
            public ulong Target;

            /// <summary>
            /// True when the branch, if taken, would have <b>skipped past</b> the
            /// dialog-calling <c>call</c>. Since the dialog actually fired, the branch
            /// was NOT taken (it fell through into the call). This is the common
            /// "skip-on-success" / "early-out" pattern.
            /// </summary>
            public bool WouldSkip;

            /// <summary>Distance in bytes from the call site back to this branch.</summary>
            public int Distance;

            /// <summary>
            /// 0 = found at the immediate call-to-dialog instruction (rec.Source).
            /// 1 = found in the direct caller (one frame up), 2 = two frames up, etc.
            /// </summary>
            public int FrameIndex;
        }

        /// <summary>
        /// Scan the dialog's immediate return site and up to <paramref name="maxFrames"/>
        /// additional app-code caller frames to find the controlling conditional branch.
        /// </summary>
        /// <param name="returnAddress"><c>CallRecord.Source</c> — address immediately
        /// AFTER the <c>call</c> that reached the hooked dialog API.</param>
        /// <param name="callerChain">Upward caller return addresses, nearest first.
        /// These are the return-address words already validated as app-code frames
        /// by <c>ExtractLocalChain</c> — each is a real return address into app code.
        /// The analyzer scans these AFTER scanning <paramref name="returnAddress"/>
        /// itself, so the whole call chain is covered.</param>
        /// <param name="is64Bit">Target's bitness.</param>
        /// <param name="readMemory">Reads <c>len</c> bytes from the target at
        /// <c>addr</c>; returns the count actually read (0 on failure).</param>
        /// <param name="maxFrames">Caller frames to walk upward (default 8).</param>
        public static BranchInfo? Analyze(
            ulong returnAddress,
            IReadOnlyList<ulong>? callerChain,
            bool is64Bit,
            Func<ulong, byte[], int> readMemory,
            int maxFrames = 8)
        {
            // Build the ordered list of return addresses: the immediate dialog
            // call site first (rec.Source), then each parent frame from the
            // already-resolved caller chain (nearest → outermost).
            var addrs = new List<ulong> { returnAddress };
            if (callerChain != null)
            {
                for (int i = 0; i < callerChain.Count && addrs.Count <= maxFrames; i++)
                {
                    ulong a = callerChain[i];
                    if (a != 0 && a != returnAddress)
                        addrs.Add(a);
                }
            }

            for (int fi = 0; fi < addrs.Count; fi++)
            {
                BranchInfo? result = AnalyzeFrame(addrs[fi], fi, is64Bit, readMemory);
                if (result != null) return result;
            }

            return null;
        }

        /// <summary>
        /// Scan one frame: locate the call instruction at <paramref name="ra"/>,
        /// disassemble up to 512 bytes backwards, and return the nearest controlling
        /// conditional branch.
        /// </summary>
        private static BranchInfo? AnalyzeFrame(
            ulong ra, int frameIndex, bool is64Bit,
            Func<ulong, byte[], int> readMemory)
        {
            if (ra < 10) return null;

            int bitness = is64Bit ? 64 : 32;

            // --- locate the call instruction whose NextIP == ra ---
            int callLen;
            ulong callSite = ra - 5;
            byte[] probe = new byte[5];
            if (readMemory(callSite, probe) < 5) return null;
            if (probe[0] != 0xE8)
            {
                // Not an E8 call rel32. Search a 32-byte window for any call
                // instruction whose NextIP lands at ra.
                const int searchLen = 32;
                ulong searchStart = ra > (ulong)searchLen ? ra - (ulong)searchLen : 0;
                byte[] searchBuf = new byte[searchLen + 15];
                int searchRead = readMemory(searchStart, searchBuf);
                if (searchRead <= 0) return null;

                var sreader = new ByteArrayCodeReader(searchBuf, 0, searchRead);
                var sdecoder = Decoder.Create(bitness, sreader, searchStart,
                    DecoderOptions.None);
                bool found = false;
                callLen = 5;
                while (sreader.CanReadByte)
                {
                    sdecoder.Decode(out Instruction si);
                    if (si.Code == Code.INVALID) break;
                    if (si.FlowControl == FlowControl.Call && si.NextIP == ra)
                    {
                        callSite = si.IP;
                        callLen = si.Length;
                        found = true;
                        break;
                    }
                    if (si.IP >= ra) break;
                }
                if (!found) return null;
            }
            else
            {
                callLen = 5;
            }

            // --- read code backwards from callSite (up to 512 bytes) ---
            const int maxScan = 512;
            int back = Math.Min(maxScan, (int)Math.Min(callSite, (ulong)int.MaxValue));
            if (back < 4) return null;

            ulong scanStart = callSite - (ulong)back;
            byte[] code = new byte[back + callLen];
            int read = readMemory(scanStart, code);
            if (read <= 4) return null;

            // --- decode forward, collect conditional branches ---
            var branches = new List<(Instruction Instr, int Offset)>();
            var reader = new ByteArrayCodeReader(code, 0, read);
            var decoder = Decoder.Create(bitness, reader, scanStart,
                DecoderOptions.None);

            while (reader.CanReadByte)
            {
                if (decoder.IP >= callSite) break;
                decoder.Decode(out Instruction instr);
                if (instr.Code == Code.INVALID) break;
                if (instr.IP >= callSite) break;

                if (IsConditionalBranch(instr))
                    branches.Add((instr, (int)(callSite - instr.IP)));

                // Stop at a function boundary (ret / int3) unless it's an
                // unconditional jump whose target lands at the call site
                // (the fall-through exit of a conditional chain).
                if (IsFunctionBoundary(instr) && instr.IP < callSite - 1)
                {
                    if (instr.FlowControl != FlowControl.UnconditionalBranch)
                        break;
                }
            }

            if (branches.Count == 0) return null;

            // --- select the best branch: nearest skip-over first ---
            // Iterate in reverse — branches are in forward code order, so
            // the last entry is physically closest to the call site.
            for (int i = branches.Count - 1; i >= 0; i--)
            {
                var (instr, dist) = branches[i];
                ulong target = instr.NearBranchTarget;
                // Skip-over: branch target is past the call instruction.
                // No upper distance limit — any branch that skips the call
                // is the controlling branch, regardless of how far it jumps.
                if (target > callSite)
                {
                    var fm = new MasmFormatter();
                    var outStr = new StringOutput();
                    fm.Format(instr, outStr);
                    return new BranchInfo
                    {
                        Address = instr.IP,
                        OpCode = instr.Code,
                        Disassembly = outStr.ToStringAndReset(),
                        Target = target,
                        WouldSkip = true,
                        Distance = dist,
                        FrameIndex = frameIndex,
                    };
                }
            }

            // Fallback: nearest branch whose target lands BEFORE the call
            // site — leading into the dialog path (a loop, or a branch that
            // falls through to the dialog code). Valid when within the
            // scan window (it wouldn't make sense otherwise).
            for (int i = branches.Count - 1; i >= 0; i--)
            {
                var (instr, dist) = branches[i];
                ulong target = instr.NearBranchTarget;
                if (target <= callSite && target >= callSite - (ulong)maxScan)
                {
                    var fm = new MasmFormatter();
                    var outStr = new StringOutput();
                    fm.Format(instr, outStr);
                    return new BranchInfo
                    {
                        Address = instr.IP,
                        OpCode = instr.Code,
                        Disassembly = outStr.ToStringAndReset(),
                        Target = target,
                        WouldSkip = false,
                        Distance = dist,
                        FrameIndex = frameIndex,
                    };
                }
            }

            return null;
        }

        private static bool IsConditionalBranch(in Instruction instr)
        {
            if (instr.FlowControl != FlowControl.ConditionalBranch) return false;
            return instr.Op0Kind == OpKind.NearBranch16 ||
                   instr.Op0Kind == OpKind.NearBranch32 ||
                   instr.Op0Kind == OpKind.NearBranch64;
        }

        private static bool IsFunctionBoundary(in Instruction instr) =>
            instr.FlowControl == FlowControl.Return ||
            instr.FlowControl == FlowControl.UnconditionalBranch ||
            instr.Code == Code.Int3;
    }
}