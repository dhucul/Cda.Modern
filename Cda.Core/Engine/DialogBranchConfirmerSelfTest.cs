using System;
using Iced.Intel;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Locks down <see cref="DialogBranchConfirmer.Taken"/> — the Jcc-from-EFLAGS table that
    /// turns a hardware-breakpoint hit into a real taken/not-taken. Pure and in-process (no
    /// target): every conditional mnemonic is checked against all 32 arithmetic-flag states,
    /// plus the jcxz/loop count edge cases. A regression here would silently invert a gate.
    /// </summary>
    public static class DialogBranchConfirmerSelfTest
    {
        public static string Run()
        {
            const uint CF = 0x1, PF = 0x4, ZF = 0x40, SF = 0x80, OF = 0x800;

            var cases = new (Code code, string name, Func<bool, bool, bool, bool, bool, bool> want)[]
            {
                (Code.Jo_rel8_64,  "jo",  (cf, pf, zf, sf, of) => of),
                (Code.Jno_rel8_64, "jno", (cf, pf, zf, sf, of) => !of),
                (Code.Jb_rel8_64,  "jb",  (cf, pf, zf, sf, of) => cf),
                (Code.Jae_rel8_64, "jae", (cf, pf, zf, sf, of) => !cf),
                (Code.Je_rel8_64,  "je",  (cf, pf, zf, sf, of) => zf),
                (Code.Jne_rel8_64, "jne", (cf, pf, zf, sf, of) => !zf),
                (Code.Jbe_rel8_64, "jbe", (cf, pf, zf, sf, of) => cf || zf),
                (Code.Ja_rel8_64,  "ja",  (cf, pf, zf, sf, of) => !cf && !zf),
                (Code.Js_rel8_64,  "js",  (cf, pf, zf, sf, of) => sf),
                (Code.Jns_rel8_64, "jns", (cf, pf, zf, sf, of) => !sf),
                (Code.Jp_rel8_64,  "jp",  (cf, pf, zf, sf, of) => pf),
                (Code.Jnp_rel8_64, "jnp", (cf, pf, zf, sf, of) => !pf),
                (Code.Jl_rel8_64,  "jl",  (cf, pf, zf, sf, of) => sf != of),
                (Code.Jge_rel8_64, "jge", (cf, pf, zf, sf, of) => sf == of),
                (Code.Jle_rel8_64, "jle", (cf, pf, zf, sf, of) => zf || (sf != of)),
                (Code.Jg_rel8_64,  "jg",  (cf, pf, zf, sf, of) => !zf && (sf == of)),
            };

            foreach (var c in cases)
            {
                for (int bits = 0; bits < 32; bits++)
                {
                    bool cf = (bits & 1) != 0, pf = (bits & 2) != 0, zf = (bits & 4) != 0,
                         sf = (bits & 8) != 0, of = (bits & 16) != 0;
                    uint ef = (cf ? CF : 0) | (pf ? PF : 0) | (zf ? ZF : 0) | (sf ? SF : 0) | (of ? OF : 0);
                    bool got = DialogBranchConfirmer.Taken(c.code, ef, 0, is64: true);
                    bool want = c.want(cf, pf, zf, sf, of);
                    if (got != want)
                        return $"FAIL: {c.name} @ cf{B(cf)}pf{B(pf)}zf{B(zf)}sf{B(sf)}of{B(of)} got {got}, want {want}.";
                }
            }

            // Count-based branches (no flag condition).
            if (!DialogBranchConfirmer.Taken(Code.Jrcxz_rel8_64, 0, 0, true))  return "FAIL: jrcxz rcx=0 should take.";
            if ( DialogBranchConfirmer.Taken(Code.Jrcxz_rel8_64, 0, 5, true))  return "FAIL: jrcxz rcx=5 should fall through.";
            if (!DialogBranchConfirmer.Taken(Code.Jecxz_rel8_64, 0, 0x1_0000_0000UL, true)) return "FAIL: jecxz masks to 32 bits (ecx=0).";
            if (!DialogBranchConfirmer.Taken(Code.Loop_rel8_64_RCX, 0, 3, true)) return "FAIL: loop rcx=3 -> 2 != 0 should take.";
            if ( DialogBranchConfirmer.Taken(Code.Loop_rel8_64_RCX, 0, 1, true)) return "FAIL: loop rcx=1 -> 0 should fall through.";
            if (!DialogBranchConfirmer.Taken(Code.Loope_rel8_64_RCX, ZF, 3, true)) return "FAIL: loope rcx=3,zf should take.";
            if ( DialogBranchConfirmer.Taken(Code.Loope_rel8_64_RCX, 0, 3, true))  return "FAIL: loope rcx=3,!zf should fall through.";

            // Decision state machine (the failing case): a `je` and a nearer `jbe`, both
            // entry-gates into the box. Register nearest-first [jbe, je]; in a pass the
            // FARTHER je executes first. With input a!=7 / x<=4 the je is NOT taken and the
            // jbe IS taken → the confirmer must name the jbe, not the je.
            string? sm = StateMachine();
            if (sm != null) return "FAIL: " + sm;

            return "PASS: Jcc condition table (16 mnemonics × 32 flag states) + jcxz/loop edge cases + decision state machine.";
        }

        private static string? StateMachine()
        {
            const uint CF = 0x1;
            const ulong jbeAddr = 0x1010, jeAddr = 0x1000;

            var conf = new DialogBranchConfirmer();
            var arm = conf.Register(0xC0DE, new[]
            {
                new DialogBranchConfirmer.Candidate(jbeAddr, Code.Jbe_rel8_64, BranchRole.EntryGate, "jbe short 0000000000001040h"), // nearest → DR0
                new DialogBranchConfirmer.Candidate(jeAddr,  Code.Je_rel8_64,  BranchRole.EntryGate, "je short 0000000000001040h"),  // farther → DR1
            });
            if (arm.Count != 2 || arm[0] != jbeAddr || arm[1] != jeAddr)
                return "Register order (nearest-first) wrong.";

            // Farther je executes first: a!=7 → je NOT taken (ZF clear) → does not route in.
            var jeHit = new FakeCtx { InstructionPointer = jeAddr, EFlags = 0 /* ZF=0 */ };
            if (conf.OnBreakpointHit(0xC0DE, 1, jeHit) != null)
                return "je (not taken) should not confirm.";

            // Nearer jbe next: x<=4 → jbe taken (CF set) → routes into the dialog.
            var jbeHit = new FakeCtx { InstructionPointer = jbeAddr, EFlags = CF };
            var c = conf.OnBreakpointHit(0xC0DE, 0, jbeHit);
            if (c == null) return "jbe (taken) should confirm.";
            if (c.BranchAddress != jbeAddr) return $"confirmed 0x{c.BranchAddress:X}, expected the jbe 0x{jbeAddr:X}.";
            if (!c.Text.Contains("jbe") || !c.Text.Contains("→ dialog") || !c.Text.Contains("[confirmed]"))
                return "confirmation text malformed: " + c.Text;
            if (!conf.IsConfirmed(0xC0DE)) return "call site should read as confirmed.";

            // A skip-over that FELL THROUGH (dialog fired) routes in when NOT taken.
            var conf2 = new DialogBranchConfirmer();
            conf2.Register(0xBEEF, new[]
            {
                new DialogBranchConfirmer.Candidate(0x2000, Code.Je_rel8_64, BranchRole.SkipOver, "je short 0000000000002050h"),
            });
            var skipHit = new FakeCtx { InstructionPointer = 0x2000, EFlags = 0 /* je not taken → fell through */ };
            var sc = conf2.OnBreakpointHit(0xBEEF, 0, skipHit);
            if (sc == null || !sc.Text.Contains("(not taken)")) return "skip-over not-taken should confirm as '(not taken)'.";

            // The exact shape MSVC /O2 emits for `if (a==7 || x<=4) MessageBox` (dlgtest):
            //   je  boxpath   (entry-gate — the STATIC guess)
            //   ja  skip      (skip-over guard — nearest to the call)
            // For a=3,x=2 the je is NOT taken and the ja falls through (CF=1 → not taken),
            // so the real gate is the ja. Register nearest-first [ja, je].
            var conf3 = new DialogBranchConfirmer();
            const ulong jaAddr = 0x300E, jeAddr2 = 0x3007;
            conf3.Register(0xF00D, new[]
            {
                new DialogBranchConfirmer.Candidate(jaAddr,  Code.Ja_rel8_64, BranchRole.SkipOver,  "ja short 0000000000003029h"),  // nearest → DR0
                new DialogBranchConfirmer.Candidate(jeAddr2, Code.Je_rel8_64, BranchRole.EntryGate, "je short 0000000000003010h"),  // farther → DR1
            });
            // je executes first (lower address): a!=7 → ZF clear → not taken → not routed.
            if (conf3.OnBreakpointHit(0xF00D, 1, new FakeCtx { InstructionPointer = jeAddr2, EFlags = 0 }) != null)
                return "dlgtest: je (not taken) should not confirm.";
            // ja next: x=2, cmp edx,4 → CF=1 → ja not taken → skip-over fell through → routes in.
            var jc = conf3.OnBreakpointHit(0xF00D, 0, new FakeCtx { InstructionPointer = jaAddr, EFlags = CF });
            if (jc == null || jc.BranchAddress != jaAddr) return "dlgtest: the ja (fell through) should confirm.";
            if (!jc.Text.Contains("ja") || !jc.Text.Contains("(not taken)")) return "dlgtest: confirm text malformed: " + jc.Text;

            // Premature-disarm guard (`if (a && b)`: two skip-overs, both fall through). The
            // FARTHER one (drIndex 1) executes first and routes in — but the probe must NOT be
            // resolved yet, else it would disarm before the nearer (drIndex 0) fires and report
            // the wrong branch. Only once the nearest routes in is it resolved.
            var conf4 = new DialogBranchConfirmer();
            conf4.Register(0xAAAA, new[]
            {
                new DialogBranchConfirmer.Candidate(0x400E, Code.Je_rel8_64, BranchRole.SkipOver, "je short 0000000000004050h"), // near → DR0
                new DialogBranchConfirmer.Candidate(0x4007, Code.Je_rel8_64, BranchRole.SkipOver, "je short 0000000000004050h"), // far  → DR1
            });
            var far = conf4.OnBreakpointHit(0xAAAA, 1, new FakeCtx { InstructionPointer = 0x4007, EFlags = 0 });
            if (far == null || far.BranchAddress != 0x4007) return "&&: farther skip-over should emit an interim confirmation.";
            if (conf4.IsResolved(0xAAAA)) return "&&: must NOT resolve on the farther branch (would disarm before the nearer fires).";
            var near = conf4.OnBreakpointHit(0xAAAA, 0, new FakeCtx { InstructionPointer = 0x400E, EFlags = 0 });
            if (near == null || near.BranchAddress != 0x400E) return "&&: nearer skip-over should override to the nearest gate.";
            if (!conf4.IsResolved(0xAAAA)) return "&&: should resolve once the nearest gate routed in.";

            return null;
        }

        // A minimal IThreadContext for driving the confirmer without a live thread.
        private sealed class FakeCtx : IThreadContext
        {
            public bool Is64 { get; set; } = true;
            public uint EFlags { get; set; }
            public ulong Dr6 { get; set; }
            public ulong CountRegister { get; set; }
            public ulong InstructionPointer { get; set; }
            public ulong StackPointer { get; set; }
            public void SetBreakpoints(ulong[] addrs) { }
            public DebugRegisterState CaptureDebugRegisters() => default;
            public void RestoreDebugRegisters(DebugRegisterState state) { }
            public bool Apply(IntPtr hThread) => true;
            public void Dispose() { }
        }

        private static string B(bool v) => v ? "1" : "0";
    }
}
