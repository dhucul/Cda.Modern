using System;
using System.Collections.Generic;
using Iced.Intel;

namespace Cda.Core.Engine
{
    /// <summary>
    /// A gating branch's static geometry relative to the dialog <c>call</c>, which
    /// fixes what its RUNTIME direction means. <see cref="SkipOver"/> jumps past the
    /// call (so it gates the dialog by falling through — routes in when NOT taken);
    /// <see cref="EntryGate"/> jumps forward past a skip-over guard into the box path
    /// (routes in when TAKEN); <see cref="IntoPath"/> lands at/before the call some
    /// other way (routes in when TAKEN). Used by <see cref="DialogBranchConfirmer"/>
    /// to decide whether an observed taken/not-taken actually reached the dialog.
    /// </summary>
    public enum BranchRole { SkipOver, EntryGate, IntoPath }

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

            /// <summary>
            /// True when this is a <b>short-circuit entry gate</b>: a conditional branch
            /// that, when taken, jumps <b>into</b> the dialog path — leaping past a later
            /// skip-over guard straight toward the <c>call</c>. This is the
            /// <c>if (a || …) show();</c> shape, where the branch closest to the call is
            /// only the OR's final fall-through test and the branch that actually routes
            /// to the dialog sits a few instructions <b>above</b> it. Mutually exclusive
            /// with <see cref="WouldSkip"/>.
            /// </summary>
            public bool EntryGate;

            /// <summary>Distance in bytes from the call site back to this branch.</summary>
            public int Distance;

            /// <summary>
            /// 0 = found at the immediate call-to-dialog instruction (rec.Source).
            /// 1 = found in the direct caller (one frame up), 2 = two frames up, etc.
            /// </summary>
            public int FrameIndex;

            /// <summary>
            /// The <c>call</c> instruction this branch gates — the frame's call site.
            /// A stable per-code-path key that the hardware branch confirmer and the
            /// UI use to correlate a runtime-confirmed direction back to this dialog row.
            /// </summary>
            public ulong CallSite;

            /// <summary>The branch's static geometry role (skip-over / entry-gate / into-path).</summary>
            public BranchRole Role;
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
            int maxFrames = 8,
            Func<ulong, ulong>? resolveFunctionStart = null)
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
                BranchInfo? result = AnalyzeFrame(
                    addrs[fi], fi, is64Bit, readMemory, resolveFunctionStart);
                if (result != null) return result;
            }

            return null;
        }

        // How far back from a call site we decode looking for its gating branches.
        private const int MaxScan = 1024;

        /// <summary>
        /// Scan one frame and pick the single controlling conditional branch: locate the
        /// <c>call</c> at <paramref name="ra"/>, decode backwards, then choose the gate —
        /// short-circuit entry-gate (nearest first), else nearest skip-over, else nearest
        /// into-path. Shares its decode with <see cref="CollectCandidates"/>.
        /// </summary>
        private static BranchInfo? AnalyzeFrame(
            ulong ra, int frameIndex, bool is64Bit,
            Func<ulong, byte[], int> readMemory,
            Func<ulong, ulong>? resolveFunctionStart)
        {
            int bitness = is64Bit ? 64 : 32;
            var branches = DecodeFrameBranches(
                ra, bitness, readMemory, resolveFunctionStart, out ulong callSite);
            if (branches == null || branches.Count == 0) return null;

            // (1) short-circuit ENTRY GATE — a branch that jumps FORWARD, past a later
            // skip-over guard, into the box path (the `if (a || b …) show();` shape). When
            // SEVERAL such branches exist (e.g. `je` then `jbe`, each leaping the guard),
            // the one actually hit is the LAST test before the box, so scan nearest-first.
            // The "leaps a guard" test keeps this off ordinary arg-setup jumps.
            for (int i = branches.Count - 1; i >= 0; i--)
            {
                var (instr, dist) = branches[i];
                ulong target = instr.NearBranchTarget;
                if (target <= instr.IP || target > callSite) continue; // must jump forward into pre-call path
                if (LeapsGuard(branches, i, target, callSite))
                    return MakeBranchInfo(instr, callSite, BranchRole.EntryGate, dist, frameIndex);
            }

            // (2) nearest SKIP-OVER — target past the call. The dialog fired, so it fell
            // through (not taken): the common early-out guard.
            for (int i = branches.Count - 1; i >= 0; i--)
            {
                var (instr, dist) = branches[i];
                if (instr.NearBranchTarget > callSite)
                    return MakeBranchInfo(instr, callSite, BranchRole.SkipOver, dist, frameIndex);
            }

            // (3) fallback — nearest branch landing at/before the call (a loop or a
            // fall-through into the dialog code) within the scan window.
            for (int i = branches.Count - 1; i >= 0; i--)
            {
                var (instr, dist) = branches[i];
                ulong target = instr.NearBranchTarget;
                if (target <= callSite && target >= callSite - (ulong)MaxScan)
                    return MakeBranchInfo(instr, callSite, BranchRole.IntoPath, dist, frameIndex);
            }

            return null;
        }

        /// <summary>
        /// Collect the nearest <paramref name="maxCandidates"/> conditional branches above
        /// the dialog call (nearest-first), each tagged with its <see cref="BranchRole"/> and
        /// the frame's <see cref="BranchInfo.CallSite"/>. This is the set the hardware branch
        /// confirmer arms in DR0–DR3 to observe which one the CPU actually took. Uses the
        /// first frame that yields any branches — the same frame walk <see cref="Analyze"/>
        /// uses — so the static guess and the probe target the same code path.
        /// </summary>
        public static IReadOnlyList<BranchInfo> CollectCandidates(
            ulong returnAddress,
            IReadOnlyList<ulong>? callerChain,
            bool is64Bit,
            Func<ulong, byte[], int> readMemory,
            int maxCandidates = 4,
            int maxFrames = 8,
            Func<ulong, ulong>? resolveFunctionStart = null)
        {
            if (maxCandidates < 0) throw new ArgumentOutOfRangeException(nameof(maxCandidates));
            if (maxFrames < 0) throw new ArgumentOutOfRangeException(nameof(maxFrames));
            if (maxCandidates == 0) return Array.Empty<BranchInfo>();
            var addrs = new List<ulong> { returnAddress };
            if (callerChain != null)
            {
                for (int i = 0; i < callerChain.Count && addrs.Count <= maxFrames; i++)
                {
                    ulong a = callerChain[i];
                    if (a != 0 && a != returnAddress) addrs.Add(a);
                }
            }

            int bitness = is64Bit ? 64 : 32;
            for (int fi = 0; fi < addrs.Count; fi++)
            {
                var branches = DecodeFrameBranches(
                    addrs[fi], bitness, readMemory, resolveFunctionStart, out ulong callSite);
                if (branches == null || branches.Count == 0) continue;

                // branches are in forward code order → the last entries are nearest the call.
                var result = new List<BranchInfo>(Math.Min(maxCandidates, branches.Count));
                for (int i = branches.Count - 1; i >= 0 && result.Count < maxCandidates; i--)
                {
                    var (instr, dist) = branches[i];
                    result.Add(MakeBranchInfo(instr, callSite, RoleOf(branches, i, callSite), dist, fi));
                }
                return result;
            }
            return Array.Empty<BranchInfo>();
        }

        // Locate the call at `ra` and decode backwards, returning the conditional branches
        // above it in forward code order (with each branch's byte-distance to the call), or
        // null if the site/code can't be read. Shared by AnalyzeFrame and CollectCandidates
        // so both see exactly the same branch set.
        private static List<(Instruction Instr, int Offset)>? DecodeFrameBranches(
            ulong ra, int bitness, Func<ulong, byte[], int> readMemory,
            Func<ulong, ulong>? resolveFunctionStart, out ulong callSite)
        {
            callSite = 0;
            if (ra == 0) return null;

            // A return address proves that some call ended at `ra`, but not where
            // that variable-length instruction began. Decode one instruction from
            // every possible x86/x64 start in the preceding 15 bytes and accept
            // only a single unambiguous call.
            int searchLength = (int)Math.Min(15UL, ra);
            ulong searchStart = ra - (ulong)searchLength;
            byte[] search = new byte[searchLength];
            int searchRead = readMemory(searchStart, search);
            if (searchRead < searchLength) return null;
            int callLen = 0;
            int matches = 0;
            for (int offset = 0; offset < searchLength; offset++)
            {
                var searchReader = new ByteArrayCodeReader(search, offset, searchLength - offset);
                var searchDecoder = Decoder.Create(
                    bitness, searchReader, searchStart + (ulong)offset, DecoderOptions.None);
                searchDecoder.Decode(out Instruction instruction);
                if (instruction.Code == Code.INVALID ||
                    (instruction.FlowControl != FlowControl.Call &&
                     instruction.FlowControl != FlowControl.IndirectCall) ||
                    instruction.NextIP != ra)
                    continue;

                matches++;
                callSite = instruction.IP;
                callLen = instruction.Length;
            }
            if (matches != 1) return null;

            // Prefer a verified discovered-function entry. During a startup dialog,
            // however, the call can arrive before the UI's read-only function index
            // has attached. In that window the resolver is legitimately unavailable;
            // use the branch-rooted fallback below rather than hiding the Branch cell.
            ulong functionStart = resolveFunctionStart?.Invoke(callSite) ?? 0;
            if (functionStart == 0 || functionStart >= callSite ||
                callSite - functionStart > MaxScan)
                return DecodeBranchesWithoutFunctionStart(
                    callSite, callLen, bitness, readMemory);

            int back = checked((int)(callSite - functionStart));
            byte[] code = new byte[back + callLen];
            int read = readMemory(functionStart, code);
            if (read <= 4)
                return DecodeBranchesWithoutFunctionStart(
                    callSite, callLen, bitness, readMemory);

            // --- decode forward, collect conditional branches ---
            var branches = new List<(Instruction Instr, int Offset)>();
            var reader = new ByteArrayCodeReader(code, 0, read);
            var decoder = Decoder.Create(bitness, reader, functionStart, DecoderOptions.None);
            bool aligned = true;

            while (reader.CanReadByte)
            {
                if (decoder.IP >= callSite) break;
                decoder.Decode(out Instruction instr);
                if (instr.Code == Code.INVALID) { aligned = false; break; }
                if (instr.IP >= callSite) break;

                if (IsConditionalBranch(instr))
                    branches.Add((instr, (int)(callSite - instr.IP)));

                if (IsFunctionBoundary(instr) && instr.IP < callSite - 1)
                {
                    aligned = false;
                    break;
                }
            }

            return aligned && decoder.IP == callSite
                ? branches
                : DecodeBranchesWithoutFunctionStart(
                    callSite, callLen, bitness, readMemory);
        }

        // Metadata-free startup fallback. Do not decode from one arbitrary byte
        // offset (which can manufacture instructions on x86/x64). Instead, treat
        // every possible conditional-branch opcode as a candidate instruction root
        // and retain it only if decoding forward from that exact root lands on the
        // already-validated call site without crossing a return/int3 boundary.
        private static List<(Instruction Instr, int Offset)>? DecodeBranchesWithoutFunctionStart(
            ulong callSite, int callLen, int bitness,
            Func<ulong, byte[], int> readMemory)
        {
            int back = Math.Min(MaxScan, (int)Math.Min(callSite, (ulong)int.MaxValue));
            byte[]? code = null;
            ulong scanStart = 0;

            // A large request can straddle an unreadable page or precede the mapped
            // image. Shrink until the live reader can supply a complete window.
            while (back >= 16)
            {
                scanStart = callSite - (ulong)back;
                var candidate = new byte[back + callLen];
                if (readMemory(scanStart, candidate) == candidate.Length)
                {
                    code = candidate;
                    break;
                }
                back /= 2;
            }
            if (code == null) return null;

            var branches = new List<(Instruction Instr, int Offset)>();
            for (int offset = 0; offset < back; offset++)
            {
                var reader = new ByteArrayCodeReader(code, offset, code.Length - offset);
                var decoder = Decoder.Create(
                    bitness, reader, scanStart + (ulong)offset, DecoderOptions.None);
                decoder.Decode(out Instruction branch);
                if (branch.Code == Code.INVALID || !IsConditionalBranch(branch))
                    continue;

                bool validPath = true;
                while (decoder.IP < callSite)
                {
                    decoder.Decode(out Instruction instruction);
                    if (instruction.Code == Code.INVALID ||
                        instruction.IP >= callSite ||
                        (IsFunctionBoundary(instruction) &&
                         instruction.FlowControl != FlowControl.UnconditionalBranch))
                    {
                        validPath = false;
                        break;
                    }
                }
                if (!validPath || decoder.IP != callSite) continue;

                branches.Add((branch, checked((int)(callSite - branch.IP))));
            }

            branches.Sort(static (a, b) => a.Instr.IP.CompareTo(b.Instr.IP));
            return branches;
        }

        // True when branch `i` jumps forward past a skip-over guard (a later branch whose
        // target is past the call) — the short-circuit entry-gate shape.
        private static bool LeapsGuard(
            List<(Instruction Instr, int Offset)> branches, int i, ulong target, ulong callSite)
        {
            for (int j = i + 1; j < branches.Count; j++)
            {
                var (guard, _) = branches[j];
                if (guard.IP >= target) break;                 // guard must precede the landing
                if (guard.NearBranchTarget > callSite) return true;
            }
            return false;
        }

        // The static geometry role of branch `i` — fixes what its runtime direction means:
        // past the call = skip-over; forward-past-a-guard = entry-gate; else into-path.
        private static BranchRole RoleOf(
            List<(Instruction Instr, int Offset)> branches, int i, ulong callSite)
        {
            var instr = branches[i].Instr;
            ulong target = instr.NearBranchTarget;
            if (target > callSite) return BranchRole.SkipOver;
            if (target > instr.IP && LeapsGuard(branches, i, target, callSite)) return BranchRole.EntryGate;
            return BranchRole.IntoPath;
        }

        // Format a chosen branch into a BranchInfo. Shared by the selectors and by
        // CollectCandidates so the Iced formatting and role mapping live in one place.
        private static BranchInfo MakeBranchInfo(
            in Instruction instr, ulong callSite, BranchRole role, int dist, int frameIndex)
        {
            var fm = new MasmFormatter();
            var outStr = new StringOutput();
            fm.Format(instr, outStr);
            return new BranchInfo
            {
                Address = instr.IP,
                OpCode = instr.Code,
                Disassembly = outStr.ToStringAndReset(),
                Target = instr.NearBranchTarget,
                WouldSkip = role == BranchRole.SkipOver,
                EntryGate = role == BranchRole.EntryGate,
                Distance = dist,
                FrameIndex = frameIndex,
                CallSite = callSite,
                Role = role,
            };
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
