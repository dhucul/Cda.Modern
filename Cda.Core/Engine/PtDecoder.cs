using System;
using System.Collections.Generic;
using Iced.Intel;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Decodes an Intel PT process-trace buffer (from <see cref="IntelPt.ReadTrace"/>) into
    /// a confirmed dialog gating branch — on the FIRST occurrence, retroactively. The buffer
    /// is <c>IPT_TRACE_DATA</c> (8-byte header) + packed per-thread entries
    /// (<c>IPT_TRACE_HEADER{ u64 ThreadId; …; u32 RingBufferOffset; u32 TraceSize; u8 Trace[] }</c>),
    /// each <c>Trace</c> a circular PT-packet buffer.
    ///
    /// It does FULL instruction-level control-flow reconstruction (not a positional shortcut):
    /// from a PSB sync point it decodes each executed instruction (Iced over the target's live
    /// code) and follows the real control flow, consuming a TNT bit at each conditional branch,
    /// a TIP at each indirect transfer, and a return-compression bit + call stack at each RET.
    /// Every taken/not-taken is therefore attributed to the EXACT branch instruction that
    /// produced it, so a candidate that never executed simply gets no direction and can't be
    /// confirmed — eliminating the false positives a positional mapping produces on real code.
    /// Timing packets are disabled at the source. Obfuscated / self-modifying / ROP-heavy code
    /// can still desync the reconstruction; on any failure it returns null and the caller falls
    /// back (or leaves the static guess).
    /// </summary>
    public static class PtDecoder
    {
        private const int MaxSteps = 50_000; // reconstruction cap per anchor (the window is short; a runaway means a wrong-thread anchor)

        /// <summary>
        /// Confirm the gate for a dialog call, or null if it can't be reconstructed.
        /// <paramref name="dialogApiAddr"/> is the hooked API entry (the call's target);
        /// <paramref name="candidates"/> is nearest-first from
        /// <see cref="DialogBranchAnalyzer.CollectCandidates"/>; <paramref name="readCode"/>
        /// reads the target's live code (for disassembly).
        /// </summary>
        // <paramref name="keyByCallSite"/>: when true (the "read at the call" fresh-read path,
        // which watches ONE API entry that several call sites may share), the returned
        // confirmation is keyed by the RECONSTRUCTED call site — the branch's own frame — so it
        // upgrades the row of whichever call site actually fired, never a different site whose
        // request happened to arm the watch. The poll-time path leaves it false and keeps the
        // requested key (which may point a frame up, as the analyzer chose).
        public static DialogBranchConfirmer.Confirmation? TryConfirm(
            byte[] trace, ulong dialogApiAddr, ulong callSiteKey,
            IReadOnlyList<DialogBranchConfirmer.Candidate> candidates,
            bool is64, Func<ulong, byte[], int> readCode, Action<string>? diag = null,
            bool keyByCallSite = false)
        {
            if (trace == null || trace.Length < 8 || candidates.Count == 0 || dialogApiAddr == 0 || readCode == null)
            { diag?.Invoke($"reject: trace={(trace?.Length ?? 0)}B cand={candidates.Count} api=0x{dialogApiAddr:X}"); return null; }

            var candAddrs = new HashSet<ulong>();
            ulong lo = ulong.MaxValue, hi = 0;
            foreach (var c in candidates) { candAddrs.Add(c.Address); if (c.Address < lo) lo = c.Address; if (c.Address > hi) hi = c.Address; }
            // The reconstruction anchor must be app code near the gate. Bound "app" to the
            // candidates' module neighbourhood — ±256 MB comfortably covers even a large app
            // module while staying far below the system DLLs (user32 etc. at 0x7FF…), so the
            // anchor is never a system TIP.
            const ulong Win = 0x10000000;
            ulong appLo = lo > Win ? lo - Win : 0;
            ulong appHi = hi + Win;
            int bitness = is64 ? 64 : 32;
            diag?.Invoke($"api=0x{dialogApiAddr:X} cand=[{string.Join(",", CandHex(candidates))}] app=[0x{appLo:X}..0x{appHi:X}] trace={trace.Length}B");

            int pos = 8; // past IPT_TRACE_DATA { u16 ver; u16 valid; u32 size; }
            int threadIdx = 0, scanned = 0;
            while (pos + 28 <= trace.Length)
            {
                uint ringOff = BitConverter.ToUInt32(trace, pos + 20);
                uint tsz = BitConverter.ToUInt32(trace, pos + 24);
                int traceStart = pos + 28;
                if (tsz == 0 || (long)traceStart + tsz > trace.Length) break;
                ulong tid = BitConverter.ToUInt64(trace, pos + 0);
                diag?.Invoke($"thr#{threadIdx} hdr: tid=0x{tid:X} ringOff={ringOff} tsz={tsz}");
                if (ringOff <= tsz)
                {
                    scanned++;
                    var lin = Linearize(trace, traceStart, (int)tsz, (int)ringOff);
                    var res = ReconstructThread(lin, dialogApiAddr, candAddrs, appLo, appHi, bitness, readCode, diag, threadIdx);
                    if (res != null)
                    {
                        // Prefer a static candidate the analyzer flagged, IF it was actually
                        // executed and routes into the dialog (matches the UI's candidate model
                        // and the dlgtest case).
                        var taken = new bool?[candidates.Count];
                        for (int i = 0; i < candidates.Count; i++)
                            taken[i] = res.Recorded.TryGetValue(candidates[i].Address, out bool t) ? t : (bool?)null;
                        var conf = DialogBranchConfirmer.Resolve(callSiteKey, candidates, taken);
                        // Else fall back to GROUND TRUTH: the last conditional actually executed
                        // in the dialog call's own frame — "the jump that was actually hit",
                        // regardless of whether the static analyzer guessed it.
                        if (conf == null && res.GateValid)
                        {
                            string dir = res.GateDir ? "(→ dialog)" : "(not taken)";
                            conf = new DialogBranchConfirmer.Confirmation
                            {
                                CallSiteKey = callSiteKey, BranchAddress = res.GateAddr,
                                Taken = res.GateDir, Code = res.GateCode,
                                Text = $"0x{res.GateAddr:X}: {res.GateText} {dir} [confirmed·live]",
                            };
                        }
                        // Fresh-read path: re-key to the call site we actually reconstructed, so
                        // the confirmation lands on the firing call site's row.
                        if (conf != null && keyByCallSite && res.CallAt != 0) conf.CallSiteKey = res.CallAt;
                        diag?.Invoke($"thr#{threadIdx}: recorded={{{string.Join(",", DirHex(res.Recorded))}}} gate={(res.GateValid ? $"0x{res.GateAddr:X}={(res.GateDir ? "T" : "N")}" : "none")} callAt=0x{res.CallAt:X} → {(conf != null ? "CONFIRM " + conf.Text : "nothing")}");
                        if (conf != null) return conf;
                    }
                }
                threadIdx++;
                pos = traceStart + (int)tsz;
            }
            diag?.Invoke($"no confirmation (scanned {scanned}/{threadIdx} threads)");
            return null;
        }

        private static IEnumerable<string> CandHex(IReadOnlyList<DialogBranchConfirmer.Candidate> c)
        { foreach (var x in c) yield return "0x" + x.Address.ToString("X"); }
        private static IEnumerable<string> DirHex(Dictionary<ulong, bool> d)
        { foreach (var kv in d) yield return $"0x{kv.Key:X}={(kv.Value ? "T" : "N")}"; }

        // Result of reconstructing one thread up to the dialog call: which STATIC candidates
        // executed (and their directions), plus the GROUND-TRUTH gate — the last conditional
        // actually executed in the dialog call's own frame (app code), for when the static
        // candidates weren't on the real path.
        private sealed class ReconResult
        {
            public readonly Dictionary<ulong, bool> Recorded = new();
            public ulong GateAddr; public bool GateDir; public bool GateValid;
            public Code GateCode; public string GateText = "";
            public ulong CallAt; // the reconstructed instruction that reached the dialog call
        }

        // Unwrap a thread's circular buffer to chronological order (oldest at RingBufferOffset).
        private static byte[] Linearize(byte[] src, int start, int size, int ringOff)
        {
            var lin = new byte[size];
            Array.Copy(src, start + ringOff, lin, 0, size - ringOff);
            Array.Copy(src, start, lin, size - ringOff, ringOff);
            return lin;
        }

        // How many app-IP anchors to step back through, newest-first, looking for one that sits
        // BEFORE the gate. The last app IP before the dialog call can land just PAST the gating
        // branch (the gate produced no IP packet), so a single-anchor reconstruction misses it;
        // stepping back a few app-IP excursions brings the gate into the reconstructed window.
        private const int AnchorLookback = 24;

        // Reconstruct one thread's executed control flow up to its most recent call to the dialog
        // API. Collects the app-code IP anchors before that call and reconstructs from each in
        // turn (nearest→farther) until one yields the gate — a short, reliable window in the
        // app's own code. Null if the call can't be reconstructed on this thread.
        private static ReconResult? ReconstructThread(
            byte[] b, ulong dialogApiAddr, HashSet<ulong> candAddrs, ulong appLo, ulong appHi,
            int bitness, Func<ulong, byte[], int> readCode, Action<string>? diag, int threadIdx)
        {
            int first = FindPsb(b, 0);
            if (first < 0) { diag?.Invoke($"thr#{threadIdx}: {b.Length}B NO-PSB"); return null; } // no sync point
            var appAnchors = new List<(int cursor, ulong ip)>(); // app-code IP packets, in order
            int callAnchorEnd = -1;                              // #anchors before the LAST dialog TIP
            int dialTips = 0, ipPkts = 0;
            ulong ipMin = ulong.MaxValue, ipMax = 0, nearDial = 0;
            ulong lastIp = 0; int p = first;
            while (p < b.Length)
            {
                var k = NextPacket(b, p, ref lastIp, out int len, out ulong ip, out _, out _);
                if (len <= 0 || p + len > b.Length) break;
                if (k == Pk.Tip || k == Pk.Fup || k == Pk.TipPge)
                {
                    ipPkts++; if (ip < ipMin) ipMin = ip; if (ip > ipMax) ipMax = ip;
                    // track the TIP target nearest the dialog API (to spot a near-miss address)
                    ulong d = ip > dialogApiAddr ? ip - dialogApiAddr : dialogApiAddr - ip;
                    if (d < (nearDial == 0 ? ulong.MaxValue : (nearDial > dialogApiAddr ? nearDial - dialogApiAddr : dialogApiAddr - nearDial))) nearDial = ip;
                }
                if (k == Pk.Tip && ip == dialogApiAddr) { dialTips++; callAnchorEnd = appAnchors.Count; }
                else if ((k == Pk.Tip || k == Pk.Fup || k == Pk.TipPge) && ip >= appLo && ip <= appHi) appAnchors.Add((p + len, ip));
                p += len;
            }
            diag?.Invoke($"thr#{threadIdx}: {b.Length}B psb@{first} ipPkts={ipPkts} ipRange=[0x{(ipMin == ulong.MaxValue ? 0 : ipMin):X}..0x{ipMax:X}] nearDial=0x{nearDial:X} appIPs={appAnchors.Count} dialTips={dialTips} anchor={(callAnchorEnd > 0 ? $"0x{appAnchors[callAnchorEnd - 1].ip:X}" : "none")}");
            if (callAnchorEnd <= 0) return null;

            // Try anchors nearest→farther. The nearest that reaches the call proves the thread is
            // synced; keep stepping back until one captures the gate (or a static candidate).
            ReconResult? best = null;
            for (int j = callAnchorEnd - 1; j >= Math.Max(0, callAnchorEnd - AnchorLookback); j--)
            {
                var a = appAnchors[j];
                var res = ReconstructFrom(b, a.cursor, a.ip, dialogApiAddr, candAddrs, appLo, appHi, bitness, readCode, diag, threadIdx);
                if (res == null) { if (j == callAnchorEnd - 1) return null; continue; } // nearest failed → wrong thread
                if (res.GateValid || res.Recorded.Count > 0) return res;               // captured the gate
                best ??= res;                                                          // reached but no gate yet
            }
            return best;
        }

        // Reconstruct forward from a synced anchor (cursor position + IP), consuming packets
        // as instructions need them, until the dialog call is reached. Tracks per-frame the
        // last conditional actually executed in app code, so the dialog call's own frame yields
        // the real gate ("the jump actually hit") even when no static candidate is on the path.
        private static ReconResult? ReconstructFrom(
            byte[] b, int startPos, ulong startIp, ulong dialogApiAddr, HashSet<ulong> candAddrs,
            ulong appLo, ulong appHi, int bitness, Func<ulong, byte[], int> readCode,
            Action<string>? diag, int threadIdx)
        {
            var tnt = new Queue<bool>();
            var tip = new Queue<ulong>();
            var callStack = new Stack<ulong>();     // decoder's return-address stack (mirrors the CPU's)
            var result = new ReconResult();
            var recorded = result.Recorded;
            var codeBuf = new byte[16];
            int pp = startPos;
            ulong lastIp = startIp;
            ulong ip = startIp; bool synced = true, justResynced = false, sawDialog = false;

            // Per-frame "last conditional executed in app code": updated on every app-range Jcc,
            // saved across a call, restored on return, so at the dialog call it holds the caller
            // frame's own most recent conditional — the branch that gated this call.
            ulong curCondAddr = 0; bool curCondDir = false, curCondValid = false;
            var condStack = new Stack<(ulong, bool, bool)>();

            // Pump the next packet into the queues / manage sync. On a resync (after we lost the
            // stream) we drop any stale queued bits and flag it so an in-flight consume aborts
            // rather than mis-attributing a post-resync bit to the pre-resync instruction.
            bool Pump()
            {
                if (pp >= b.Length) return false;
                var k = NextPacket(b, pp, ref lastIp, out int len, out ulong pip, out ulong bits, out int tc);
                if (len <= 0 || pp + len > b.Length) { pp = b.Length; return false; }
                pp += len;
                switch (k)
                {
                    case Pk.Psb: case Pk.Ovf: case Pk.TipPgd:             // lost/paused → resync at next PGE/FUP
                        synced = false; tnt.Clear(); tip.Clear(); break;
                    case Pk.TipPge:
                        ip = pip; if (!synced) { tnt.Clear(); tip.Clear(); justResynced = true; } synced = true; break;
                    case Pk.Fup:
                        if (!synced) { ip = pip; tnt.Clear(); tip.Clear(); synced = true; justResynced = true; }
                        else tip.Enqueue(pip);
                        break;
                    case Pk.Tip:
                        if (synced) tip.Enqueue(pip);
                        else if (pip == dialogApiAddr) sawDialog = true; // don't skip the call while desynced
                        break;
                    case Pk.ShortTnt: case Pk.LongTnt:
                        if (synced) for (int i = tc - 1; i >= 0; i--) tnt.Enqueue(((bits >> i) & 1) != 0); break;
                }
                return true;
            }
            bool NextTnt(out bool bit) { while (tnt.Count == 0) { if (!synced || justResynced || !Pump()) { bit = false; return false; } } bit = tnt.Dequeue(); return true; }
            bool NextTip(out ulong t) { while (tip.Count == 0) { if (!synced || justResynced || !Pump()) { t = 0; return false; } } t = tip.Dequeue(); return true; }
            bool Lost() => !synced || justResynced; // a consume failed because we lost sync — re-decode, don't fail

            int steps = 0, badReads = 0, invalids = 0;

            ReconResult? Fail(string why)
            { diag?.Invoke($"thr#{threadIdx}: recon FAIL {why} @0x{ip:X} step{steps} depth={callStack.Count} badRd={badReads} inv={invalids}"); return null; }

            ReconResult Done(ulong callAt, bool viaJmp = false)
            {
                // Gate = the caller frame's last app-code conditional. When the dialog was
                // reached by a tail-jmp / import thunk the current frame may be that stub (no
                // conditional of its own), so fall back to the frame that jumped into it.
                ulong gAddr = 0; bool gDir = false, gValid = false;
                if (curCondValid && curCondAddr >= appLo && curCondAddr <= appHi)
                { gAddr = curCondAddr; gDir = curCondDir; gValid = true; }
                else if (viaJmp && condStack.Count > 0)
                {
                    var c = condStack.Peek();
                    if (c.Item3 && c.Item1 >= appLo && c.Item1 <= appHi) { gAddr = c.Item1; gDir = c.Item2; gValid = true; }
                }
                if (gValid)
                {
                    var (gc, gt) = FormatAt(gAddr, bitness, readCode);
                    result.GateAddr = gAddr; result.GateDir = gDir; result.GateValid = true;
                    result.GateCode = gc; result.GateText = gt;
                }
                result.CallAt = callAt;
                diag?.Invoke($"thr#{threadIdx}: reached call@0x{callAt:X} step{steps} recorded={recorded.Count}/{candAddrs.Count} gate={(result.GateValid ? $"0x{result.GateAddr:X}={(result.GateDir ? "T" : "N")}" : "none")}");
                return result;
            }

            while (steps++ < MaxSteps)
            {
                justResynced = false;
                if (sawDialog) return Done(0); // dialog TIP seen while resyncing — best-effort gate
                if (!synced) { if (!Pump()) return Fail("packets-exhausted-while-desynced"); continue; }

                int n = readCode(ip, codeBuf);
                if (n < 1) { badReads++; synced = false; tnt.Clear(); tip.Clear(); continue; }
                var dec = Decoder.Create(bitness, new ByteArrayCodeReader(codeBuf, 0, n), ip, DecoderOptions.None);
                dec.Decode(out Instruction ins);
                if (ins.Code == Code.INVALID) { invalids++; synced = false; tnt.Clear(); tip.Clear(); continue; }
                ulong next = ins.NextIP;

                switch (ins.FlowControl)
                {
                    case FlowControl.ConditionalBranch:
                        if (!NextTnt(out bool taken)) { if (Lost()) continue; return Fail("tnt-exhausted@cond"); }
                        if (candAddrs.Contains(ip)) recorded[ip] = taken;
                        if (ip >= appLo && ip <= appHi) { curCondAddr = ip; curCondDir = taken; curCondValid = true; }
                        ip = taken ? ins.NearBranchTarget : next;
                        break;

                    case FlowControl.UnconditionalBranch:
                        // A direct tail-jmp straight to the dialog API (jmp MessageBoxW) reaches
                        // the call without a CALL; don't decode on into the API.
                        if (ins.NearBranchTarget == dialogApiAddr) return Done(ip, viaJmp: true);
                        ip = ins.NearBranchTarget; // direct near jmp
                        break;

                    case FlowControl.IndirectBranch:
                    {
                        ulong jmpAt = ip;
                        if (!NextTip(out ulong jt)) { if (Lost()) continue; return Fail("tip-exhausted@ijmp"); }
                        // Import thunk (jmp [__imp_...]) or computed tail-jmp landing on the API.
                        if (jt == dialogApiAddr) return Done(jmpAt, viaJmp: true);
                        ip = jt;
                        break;
                    }

                    case FlowControl.Call:
                        if (ins.NearBranchTarget == dialogApiAddr) return Done(ip); // direct call to the dialog API
                        callStack.Push(next);
                        condStack.Push((curCondAddr, curCondDir, curCondValid));
                        curCondValid = false;
                        ip = ins.NearBranchTarget;
                        break;

                    case FlowControl.IndirectCall:
                        if (!NextTip(out ulong ct)) { if (Lost()) continue; return Fail("tip-exhausted@icall"); }
                        if (ct == dialogApiAddr) return Done(ip); // the common IAT form: call [__imp_...]
                        callStack.Push(next);
                        condStack.Push((curCondAddr, curCondDir, curCondValid));
                        curCondValid = false;
                        ip = ct;
                        break;

                    case FlowControl.Return:
                        if (callStack.Count > 0)
                        {
                            // Return compression is on by default: a RET whose target the CPU's
                            // return stack predicts is one TNT bit; we mirror that stack.
                            if (!NextTnt(out _)) { if (Lost()) continue; return Fail("tnt-exhausted@ret"); }
                            ip = callStack.Pop();
                            if (condStack.Count > 0) { var c = condStack.Pop(); curCondAddr = c.Item1; curCondDir = c.Item2; curCondValid = c.Item3; }
                            else curCondValid = false;
                        }
                        else
                        {
                            // Underflow: returning above where reconstruction began — the CPU's
                            // return stack (seeded before our anchor) is unknown to us, so the
                            // target is unrecoverable. Drop sync and resync at the next IP packet.
                            synced = false; tnt.Clear(); tip.Clear();
                        }
                        break;

                    case FlowControl.Next:
                    default: // normal instruction (or a flow we don't special-case) → advance
                        ip = next;
                        break;
                }
            }
            return Fail("max-steps"); // never reached the dialog call
        }

        // Decode + format a single instruction from the target's live code (for the confirmed
        // gate's row text). MASM style matches the analyzer's candidate disassembly.
        private static (Code, string) FormatAt(ulong addr, int bitness, Func<ulong, byte[], int> readCode)
        {
            var buf = new byte[16];
            int n = readCode(addr, buf);
            if (n < 1) return (Code.INVALID, $"branch@0x{addr:X}");
            var dec = Decoder.Create(bitness, new ByteArrayCodeReader(buf, 0, n), addr, DecoderOptions.None);
            dec.Decode(out Instruction ins);
            var fmt = new MasmFormatter();
            var so = new StringOutput();
            fmt.Format(in ins, so);
            return (ins.Code, so.ToStringAndReset());
        }

        // --- PT packet parsing ------------------------------------------------------------

        private enum Pk { Pad, Psb, PsbEnd, ShortTnt, LongTnt, Tip, TipPge, TipPgd, Fup, Mode, Cbr, Pip, Ovf, Tsc, Mtc, Cyc, Tma, Mnt, Vmcs, Unknown }
        private static readonly int[] IpBytesTab = { 0, 2, 4, 6, 6, 0, 8, 0 };

        private static int FindPsb(byte[] b, int from)
        {
            for (int i = from; i + 4 <= b.Length; i++)
                if (b[i] == 0x02 && b[i + 1] == 0x82 && b[i + 2] == 0x02 && b[i + 3] == 0x82) return i;
            return -1;
        }

        private static Pk NextPacket(byte[] b, int pos, ref ulong lastIp, out int len, out ulong ip, out ulong tnt, out int tc)
        {
            ip = 0; tnt = 0; tc = 0; byte c = b[pos];
            if (c == 0x00) { len = 1; return Pk.Pad; }
            if (c == 0x02 && pos + 4 <= b.Length && b[pos + 1] == 0x82 && b[pos + 2] == 0x02 && b[pos + 3] == 0x82) { len = 16; return Pk.Psb; }
            if (c == 0x02)
            {
                byte c2 = pos + 1 < b.Length ? b[pos + 1] : (byte)0;
                switch (c2)
                {
                    case 0x23: len = 2; return Pk.PsbEnd;
                    case 0x03: len = 4; return Pk.Cbr;
                    case 0x43: len = 8; return Pk.Pip;
                    case 0x73: len = 7; return Pk.Tma;
                    case 0xA3: len = 8; { ulong pl = 0; for (int k = 0; k < 6; k++) pl |= (ulong)b[pos + 2 + k] << (8 * k); tc = LongTnt(pl, out tnt); } return Pk.LongTnt;
                    case 0xC3: len = 11; return Pk.Mnt;
                    case 0xC8: len = 7; return Pk.Vmcs;
                    case 0xF3: len = 2; return Pk.Ovf;
                    default: len = 2; return Pk.Unknown;
                }
            }
            int low5 = c & 0x1F;
            if (low5 == 0x0D || low5 == 0x11 || low5 == 0x01 || low5 == 0x1D)
            {
                int form = (c >> 5) & 7; len = 1 + IpBytesTab[form]; DecodeIp(b, pos + 1, form, ref lastIp, out ip);
                return low5 == 0x0D ? Pk.Tip : low5 == 0x11 ? Pk.TipPge : low5 == 0x01 ? Pk.TipPgd : Pk.Fup;
            }
            if (c == 0x99) { len = 2; return Pk.Mode; }
            if (c == 0x19) { len = 8; return Pk.Tsc; }
            if (c == 0x59) { len = 2; return Pk.Mtc; }
            if ((c & 0x03) == 0x03) { int l = 1; while (pos + l < b.Length && (b[pos + l - 1] & 1) != 0) l++; len = Math.Max(1, l); return Pk.Cyc; }
            if ((c & 0x01) == 0) { len = 1; tc = ShortTnt(c, out tnt); return Pk.ShortTnt; }
            len = 1; return Pk.Unknown;
        }

        private static void DecodeIp(byte[] b, int pos, int form, ref ulong lastIp, out ulong ip)
        {
            ip = lastIp;
            switch (form)
            {
                case 0: return;
                case 1: ip = (lastIp & ~0xFFFFUL) | Read(b, pos, 2); break;
                case 2: ip = (lastIp & ~0xFFFFFFFFUL) | Read(b, pos, 4); break;
                case 3: ip = (lastIp & ~0xFFFFFFFFFFFFUL) | Read(b, pos, 6); break;
                case 4: { ulong v = Read(b, pos, 6); ip = (v & 0x800000000000UL) != 0 ? v | 0xFFFF000000000000UL : v; break; }
                case 6: ip = Read(b, pos, 8); break;
                default: return;
            }
            lastIp = ip;
        }

        private static ulong Read(byte[] b, int pos, int n) { ulong v = 0; for (int k = 0; k < n; k++) v |= (ulong)b[pos + k] << (8 * k); return v; }

        private static int ShortTnt(byte c, out ulong bits)
        {
            int val = c >> 1;
            int stop = 31 - System.Numerics.BitOperations.LeadingZeroCount((uint)val);
            bits = 0; int n = 0;
            for (int bit = stop - 1; bit >= 0; bit--) { bits = (bits << 1) | (((ulong)val >> bit) & 1); n++; }
            return n;
        }
        private static int LongTnt(ulong payload, out ulong bits)
        {
            if (payload == 0) { bits = 0; return 0; }
            int stop = 63 - System.Numerics.BitOperations.LeadingZeroCount(payload);
            bits = 0; int n = 0;
            for (int bit = stop - 1; bit >= 0; bit--) { bits = (bits << 1) | ((payload >> bit) & 1); n++; }
            return n;
        }
    }
}
