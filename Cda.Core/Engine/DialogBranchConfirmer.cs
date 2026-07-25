using System;
using System.Collections.Generic;
using Iced.Intel;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Turns the STATIC guess about a dialog's gating branch into RUNTIME GROUND TRUTH.
    /// The static <see cref="DialogBranchAnalyzer"/> can only guess which of several jumps
    /// routes into a message box; this observes the CPU directly. The debug loop arms the
    /// candidate branches in hardware debug registers (DR0–DR3); each faults BEFORE it
    /// executes, so the thread's EFLAGS at the fault are exactly the flags that jump will
    /// consume — and a hardware execute breakpoint fires ONLY on instructions actually
    /// executed, so a branch skipped by an earlier taken jump is never even seen. This
    /// class evaluates the faulting Jcc against those flags (<see cref="Taken"/>) and
    /// decides whether its real direction routes into the dialog. It is dependency-free
    /// (no debug-loop or WPF types) and owned entirely by the debug-loop thread.
    ///
    /// Correctness for the failing case (`je` into box, then a nearer `jbe` into box):
    /// the `je` faults, evaluates NOT-taken → does not route in → ignored; the `jbe`
    /// faults, evaluates TAKEN → routes in → becomes the confirmed gate. No heuristic.
    /// </summary>
    public sealed class DialogBranchConfirmer
    {
        /// <summary>One branch to arm and observe.</summary>
        public readonly struct Candidate
        {
            /// <summary>Virtual address of the Jcc instruction (the DR breakpoint address).</summary>
            public readonly ulong Address;
            /// <summary>Iced opcode, so its condition can be evaluated from EFLAGS.</summary>
            public readonly Code Code;
            /// <summary>Static geometry, which fixes what a taken/not-taken means.</summary>
            public readonly BranchRole Role;
            /// <summary>Formatted mnemonic + target, for the confirmed row text.</summary>
            public readonly string Disassembly;

            public Candidate(ulong address, Code code, BranchRole role, string disassembly)
            {
                Address = address; Code = code; Role = role; Disassembly = disassembly;
            }
        }

        /// <summary>The confirmed gate for a call site, once observed at runtime.</summary>
        public sealed class Confirmation
        {
            public ulong CallSiteKey;
            public ulong BranchAddress;
            public bool Taken;
            public Code Code;
            public string Text = "";
        }

        private sealed class State
        {
            public Candidate[] ByDrIndex = Array.Empty<Candidate>(); // DR index → candidate
            public int BestDrIndex = int.MaxValue;                   // nearest routing-in seen (small = nearer)
            public Confirmation? Best;
            public int Hits;                                         // candidate #DBs observed (give-up backstop)
        }

        // If the nearest candidate never routes in, the probe would hold its DR slots forever;
        // after this many candidate hits without reaching the nearest gate, give up and free
        // the slots for other call sites (the best-so-far confirmation, if any, already stands).
        private const int GiveUpHits = 500;

        // Keyed by call site (the candidates are unique to one code path, so no thread id is
        // needed to correlate). Accessed only from the debug-loop thread.
        private readonly Dictionary<ulong, State> _byCallSite = new();

        /// <summary>
        /// Register a call site's candidate branches (nearest-first) and return the ≤4
        /// addresses to arm in DR0–DR3 (DR index = position here). No-op (empty) if this
        /// call site is already confirmed. Re-registering an un-confirmed site refreshes it.
        /// </summary>
        public IReadOnlyList<ulong> Register(ulong callSiteKey, IReadOnlyList<Candidate> candidates)
        {
            // Never re-register a call site we already track — that would clobber its
            // in-progress best/hit state. The UI requests each call site once.
            if (_byCallSite.ContainsKey(callSiteKey))
                return Array.Empty<ulong>();

            var arm = new List<ulong>(4);
            var byIdx = new List<Candidate>(4);
            foreach (var c in candidates)
            {
                if (c.Address == 0 || arm.Contains(c.Address)) continue;
                if (arm.Count >= 4) break;
                arm.Add(c.Address);
                byIdx.Add(c);
            }
            if (arm.Count == 0) return arm;
            _byCallSite[callSiteKey] = new State { ByDrIndex = byIdx.ToArray() };
            return arm;
        }

        /// <summary>
        /// A candidate branch faulted. Evaluate its real direction from the thread context
        /// and, if it routes into the dialog and is nearer the call than any gate seen so
        /// far, record and return the confirmation; else null. Hits within one pass arrive
        /// farthest→nearest, so the best converges monotonically to the nearest routing-in
        /// branch — the one actually hit to reach the dialog.
        /// </summary>
        internal Confirmation? OnBreakpointHit(ulong callSiteKey, int drIndex, IThreadContext ctx)
        {
            if (!_byCallSite.TryGetValue(callSiteKey, out var st)) return null;
            if (drIndex < 0 || drIndex >= st.ByDrIndex.Length) return null;
            var cand = st.ByDrIndex[drIndex];
            if (ctx.InstructionPointer != cand.Address) return null; // stray #DB — not this branch

            st.Hits++;
            bool taken = Taken(cand.Code, ctx.EFlags, ctx.CountRegister, ctx.Is64);
            if (!RoutesIntoDialog(cand.Role, taken)) return null;
            if (drIndex >= st.BestDrIndex) return null;              // a nearer gate already stands

            st.BestDrIndex = drIndex;
            string dir = cand.Role == BranchRole.SkipOver ? "(not taken)" : "(→ dialog)";
            var conf = new Confirmation
            {
                CallSiteKey = callSiteKey,
                BranchAddress = cand.Address,
                Taken = taken,
                Code = cand.Code,
                Text = $"0x{cand.Address:X}: {cand.Disassembly} {dir} [confirmed]",
            };
            st.Best = conf;
            return conf;
        }

        public bool IsConfirmed(ulong callSiteKey)
            => _byCallSite.TryGetValue(callSiteKey, out var st) && st.Best != null;

        /// <summary>
        /// The probe for this call site can be disarmed: the NEAREST candidate has routed in
        /// (<c>BestDrIndex == 0</c> — nothing nearer can override it, so it is final), or the
        /// give-up backstop tripped. It is deliberately NOT "any confirmation": disarming the
        /// instant a FARTHER candidate routes in would cut the pass off before the nearer one
        /// fires and report the wrong branch.
        /// </summary>
        public bool IsResolved(ulong callSiteKey)
            => _byCallSite.TryGetValue(callSiteKey, out var st) &&
               (st.BestDrIndex == 0 || st.Hits >= GiveUpHits);

        public void Forget(ulong callSiteKey) => _byCallSite.Remove(callSiteKey);

        // A skip-over gates by falling through (routes in when NOT taken); an entry-gate /
        // into-path routes in when TAKEN.
        private static bool RoutesIntoDialog(BranchRole role, bool taken)
            => role == BranchRole.SkipOver ? !taken : taken;

        /// <summary>
        /// Build a confirmation from a full set of observed candidate directions (used by the
        /// Intel PT path, which reads every branch's taken/not-taken at once rather than one
        /// #DB at a time). <paramref name="taken"/>[i] is candidate <paramref name="candidates"/>[i]'s
        /// real direction (null = not observed). Picks the NEAREST candidate that routes into
        /// the dialog — the same rule the DR path converges to. Null if none routes in.
        /// </summary>
        public static Confirmation? Resolve(ulong callSiteKey,
            IReadOnlyList<Candidate> candidates, IReadOnlyList<bool?> taken)
        {
            for (int i = 0; i < candidates.Count; i++) // candidates are nearest-first
            {
                if (i >= taken.Count || taken[i] is not bool t) continue;
                if (!RoutesIntoDialog(candidates[i].Role, t)) continue;
                string dir = candidates[i].Role == BranchRole.SkipOver ? "(not taken)" : "(→ dialog)";
                return new Confirmation
                {
                    CallSiteKey = callSiteKey,
                    BranchAddress = candidates[i].Address,
                    Taken = t,
                    Code = candidates[i].Code,
                    Text = $"0x{candidates[i].Address:X}: {candidates[i].Disassembly} {dir} [confirmed]",
                };
            }
            return null;
        }

        /// <summary>
        /// True iff the conditional branch <paramref name="code"/> would be TAKEN given the
        /// arithmetic flags <paramref name="eflags"/> (and the count register for jcxz/loop).
        /// The hardware breakpoint faults before the branch runs, so these are exactly the
        /// flags it will consume. Covers every Jcc variant plus the count-based branches —
        /// pure and unit-tested (<see cref="DialogBranchConfirmerSelfTest"/>).
        /// </summary>
        public static bool Taken(Code code, uint eflags, ulong countReg, bool is64)
        {
            const uint CF = 0x0001, PF = 0x0004, ZF = 0x0040, SF = 0x0080, OF = 0x0800;
            bool cf = (eflags & CF) != 0, pf = (eflags & PF) != 0, zf = (eflags & ZF) != 0,
                 sf = (eflags & SF) != 0, of = (eflags & OF) != 0;

            // Count-based branches first: their outcome is not a flag condition. jcxz/jecxz/
            // jrcxz test the RAW register; loop* DECREMENT the count before testing, and the
            // #DB is pre-execution, so test against countReg-1 at the right width.
            switch (code.Mnemonic())
            {
                case Mnemonic.Jcxz:  return (ushort)countReg == 0;
                case Mnemonic.Jecxz: return (uint)countReg == 0;
                case Mnemonic.Jrcxz: return countReg == 0;
                case Mnemonic.Loop:   return DecCount(countReg, is64) != 0;
                case Mnemonic.Loope:  return DecCount(countReg, is64) != 0 && zf;
                case Mnemonic.Loopne: return DecCount(countReg, is64) != 0 && !zf;
            }

            switch (code.ConditionCode())
            {
                case ConditionCode.o:  return of;
                case ConditionCode.no: return !of;
                case ConditionCode.b:  return cf;                 // jb/jc/jnae
                case ConditionCode.ae: return !cf;                // jae/jnb/jnc
                case ConditionCode.e:  return zf;                 // je/jz
                case ConditionCode.ne: return !zf;                // jne/jnz
                case ConditionCode.be: return cf || zf;           // jbe/jna
                case ConditionCode.a:  return !cf && !zf;         // ja/jnbe
                case ConditionCode.s:  return sf;
                case ConditionCode.ns: return !sf;
                case ConditionCode.p:  return pf;                 // jp/jpe
                case ConditionCode.np: return !pf;                // jnp/jpo
                case ConditionCode.l:  return sf != of;           // jl/jnge
                case ConditionCode.ge: return sf == of;           // jge/jnl
                case ConditionCode.le: return zf || (sf != of);   // jle/jng
                case ConditionCode.g:  return !zf && (sf == of);  // jg/jnle
                default: return false;                            // None — not a Jcc (shouldn't reach here)
            }
        }

        private static ulong DecCount(ulong countReg, bool is64)
            => is64 ? countReg - 1 : (uint)((uint)countReg - 1);
    }
}
