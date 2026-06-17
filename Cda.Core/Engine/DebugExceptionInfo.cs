using System;
using System.Runtime.InteropServices;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Decodes an EXCEPTION_DEBUG_EVENT out of a raw debug-event buffer and formats
    /// a one-line crash diagnostic for the debug-loop capture paths
    /// (<see cref="DebugLoadCapture"/>, <see cref="ChildFollowCapture"/>).
    ///
    /// The line carries what's needed to pin a crash that survives the
    /// entry-validation guard to the code that faulted: the exception code (named
    /// where known), the faulting instruction as <c>module+0xRVA</c> (so it can be
    /// correlated against the hooked functions / patch regions), the access kind or
    /// fail-fast subcode, and whether the exception was first- or last-chance.
    ///
    /// Fields are read by offset because DEBUG_EVENT is a pointer-size-dependent
    /// union; the layout mirrors the <c>U</c> computation in the debug loops
    /// (union at offset 16 on a 64-bit host, 12 on a 32-bit host). EXCEPTION_RECORD
    /// then runs: code\@0, flags\@4, nested-record\@8, address\@8+ptr,
    /// numberParameters\@8+2·ptr, information[k]\@(32+k·8 on x64 / 20+k·4 on x86),
    /// and dwFirstChance follows the whole record (\@152 on x64 / \@80 on x86).
    /// </summary>
    public static class DebugExceptionInfo
    {
        // Common crash exception codes (NTSTATUS, error severity 0xCxxxxxxx).
        public const uint ACCESS_VIOLATION    = 0xC0000005;
        public const uint IN_PAGE_ERROR       = 0xC0000006;
        public const uint ILLEGAL_INSTRUCTION = 0xC000001D;
        public const uint PRIV_INSTRUCTION    = 0xC0000096;
        public const uint INT_DIVIDE_BY_ZERO  = 0xC0000094;
        public const uint STACK_OVERFLOW      = 0xC00000FD;
        public const uint FAIL_FAST           = 0xC0000409;
        public const uint BREAKPOINT          = 0x80000003; // STATUS_BREAKPOINT (an int3)

        /// <summary>
        /// True for error-severity NTSTATUS exceptions (0xCxxxxxxx) — the hardware
        /// faults and fail-fasts that mean a crash — while excluding routine
        /// breakpoints / single-steps (warning severity) and C++/CLR exceptions
        /// (0xExxxxxxx), which are raised and handled normally by many programs.
        /// Used as a cheap gate before the fuller <see cref="Format"/> decode.
        /// </summary>
        public static bool IsCrash(uint code) => (code & 0xF0000000u) == 0xC0000000u;

        /// <summary>
        /// Interpret a process *exit* code. An NTSTATUS error value (0xCxxxxxxx)
        /// means the target crashed with that exception (named) rather than exiting
        /// normally — the way to tell a genuinely short-lived program apart from one
        /// our hooks killed. This is the post-mortem fallback: the debug-loop paths
        /// (and the startup trace's <see cref="DebugCrashWatch"/>) catch the fault
        /// live with its faulting address, so the exit code only has to confirm it.
        /// </summary>
        public static string ExitCodeNote(uint exitCode)
        {
            if ((exitCode & 0xF0000000u) == 0xC0000000u)
                return $" · {Name(exitCode)} — the target CRASHED (a hooked function likely corrupted it)";
            if (exitCode == BREAKPOINT)
                return " · STATUS_BREAKPOINT — an unhandled int3 (0xCC) killed it: either a splice ran "
                     + "into int3 padding, or the program tripped its own debug-break / anti-tamper on "
                     + "the patched code.";
            return exitCode == 0 ? " · clean exit" : " · normal exit";
        }

        /// <summary>
        /// Decode and format the crash, or return <c>null</c> when it isn't worth
        /// reporting (a first-chance access violation, which some runtimes — e.g.
        /// .NET null checks — raise and handle constantly; the genuine crash shows
        /// up as the last-chance pass). Always reports last-chance exceptions and
        /// the codes that are fatal even first-chance.
        /// </summary>
        public static string? Format(IntPtr evt, int u, uint code, int pid)
        {
            int ptr = IntPtr.Size;
            int firstChance = Marshal.ReadInt32(evt, u + (ptr == 8 ? 152 : 80)); // dwFirstChance

            bool fatalEvenFirstChance =
                code == ILLEGAL_INSTRUCTION || code == PRIV_INSTRUCTION ||
                code == STACK_OVERFLOW || code == FAIL_FAST || code == BREAKPOINT;
            if (firstChance != 0 && !fatalEvenFirstChance)
                return null; // first-chance AV / divide / in-page: wait for last-chance

            ulong faultIp = (ulong)Marshal.ReadIntPtr(evt, u + 8 + ptr).ToInt64();      // ExceptionAddress
            int nParams   = Marshal.ReadInt32(evt, u + 8 + 2 * ptr);                    // NumberParameters
            int infoOff   = u + (ptr == 8 ? 32 : 20);                                   // ExceptionInformation[0]

            string detail = "";
            if ((code == ACCESS_VIOLATION || code == IN_PAGE_ERROR) && nParams >= 2)
            {
                ulong kind = (ulong)Marshal.ReadIntPtr(evt, infoOff).ToInt64();
                ulong addr = (ulong)Marshal.ReadIntPtr(evt, infoOff + ptr).ToInt64();
                string verb = kind == 0 ? "reading" : kind == 1 ? "writing" : kind == 8 ? "executing" : "accessing";
                detail = $" {verb} 0x{addr:X}";
            }
            else if (code == FAIL_FAST && nParams >= 1)
            {
                ulong sub = (ulong)Marshal.ReadIntPtr(evt, infoOff).ToInt64();
                detail = $" subcode {sub}{FailFastNote(sub)}";
            }

            string where;
            string codeDump = "";
            try
            {
                using var tp = TargetProcess.Attach(pid, forWrite: false);
                var map = new ModuleMap(tp.EnumerateModules());
                where = map.Describe(faultIp);
                bool inModule = map.Resolve(faultIp) != null;

                // Fault context: the faulting instruction's bytes and the thread's
                // integer registers. For a null/bad-pointer access — the common
                // "a hook corrupted a value that something dereferenced later"
                // failure — this shows WHICH register went bad and what the
                // instruction was, which is the thread to pull to find the source.
                if (IsCrash(code) || code == BREAKPOINT)
                    codeDump = FaultContext(evt, tp, faultIp);

                // If the fault is in memory CDA itself allocated (a capture stub or
                // trampoline, i.e. not in any module), also dump that allocation so
                // the generated code can be decoded: a stub begins
                // 50 53 51 52 41 50 41 51 57 9C; a trampoline begins with the hooked
                // function's relocated opening bytes.
                if (!inModule && (code == BREAKPOINT || code == ILLEGAL_INSTRUCTION ||
                                  code == PRIV_INSTRUCTION || code == ACCESS_VIOLATION))
                    codeDump += DumpFaultCode(tp, faultIp);
            }
            catch { where = "0x" + faultIp.ToString("X"); }

            string chance = firstChance != 0 ? "first-chance" : "unhandled / last-chance";
            return $"crash · pid {pid} · {Name(code)} (0x{code:X8}){detail} at {where} [{chance}]{codeDump}";
        }

        // The faulting instruction's bytes plus the faulting thread's integer
        // registers. The process is stopped at the debug event, so reading the
        // thread context is safe. The register dump is x64-only (the CONTEXT layout
        // is AMD64); the instruction bytes are read either way.
        private static string FaultContext(IntPtr evt, TargetProcess tp, ulong faultIp)
        {
            var sb = new System.Text.StringBuilder();
            byte[] insn = new byte[16];
            int n = tp.ReadMemory(faultIp, insn);
            if (n > 0) sb.Append($" · insn@fault: {Hex(insn, n)}");

            if (tp.Is64Bit)
            {
                uint tid = (uint)Marshal.ReadInt32(evt, 8); // DEBUG_EVENT.dwThreadId
                IntPtr h = NativeMethods.OpenThread(NativeMethods.THREAD_GET_CONTEXT, false, tid);
                if (h != IntPtr.Zero)
                {
                    try
                    {
                        using var ctx = ThreadContextX64.Capture(h);
                        if (ctx != null) sb.Append(" · regs: " + ctx.FormatIntegerRegisters());
                    }
                    finally { NativeMethods.CloseHandle(h); }
                }
            }
            return sb.ToString();
        }

        // Read and hex-format the bytes around a fault that landed in CDA's own
        // allocated code (a stub/trampoline), plus the start of the containing
        // 64KB allocation, so the generated code can be decoded from the log. The
        // process is stopped at the debug event, so the read-only attach is safe.
        private static string DumpFaultCode(TargetProcess tp, ulong faultIp)
        {
            var sb = new System.Text.StringBuilder();
            ulong from = faultIp >= 16 ? faultIp - 16 : 0;
            byte[] buf = new byte[48];
            int n = tp.ReadMemory(from, buf);
            if (n > 0)
                sb.Append($" · bytes@0x{from:X}[fault@+{faultIp - from}]: {Hex(buf, n)}");
            ulong allocBase = faultIp & ~0xFFFFUL; // VirtualAllocEx reserves 64KB-aligned
            if (allocBase < from)
            {
                byte[] head = new byte[16];
                int hn = tp.ReadMemory(allocBase, head);
                if (hn > 0) sb.Append($" · alloc@0x{allocBase:X}: {Hex(head, hn)}");
            }
            return sb.ToString();
        }

        private static string Hex(byte[] b, int n)
        {
            var sb = new System.Text.StringBuilder(n * 3);
            for (int i = 0; i < n; i++) { if (i > 0) sb.Append(' '); sb.Append(b[i].ToString("X2")); }
            return sb.ToString();
        }

        private static string Name(uint code) => code switch
        {
            ACCESS_VIOLATION    => "ACCESS_VIOLATION",
            IN_PAGE_ERROR       => "IN_PAGE_ERROR",
            ILLEGAL_INSTRUCTION => "ILLEGAL_INSTRUCTION",
            PRIV_INSTRUCTION    => "PRIVILEGED_INSTRUCTION",
            INT_DIVIDE_BY_ZERO  => "INT_DIVIDE_BY_ZERO",
            STACK_OVERFLOW      => "STACK_OVERFLOW",
            FAIL_FAST           => "FAIL_FAST",
            BREAKPOINT          => "BREAKPOINT (int3)",
            _                   => "EXCEPTION",
        };

        // The fail-fast subcodes most relevant to a splicing tool — a corrupted
        // stack cookie or a Control-Flow-Guard check failure points straight at a
        // bad splice or a CFG interaction. The raw subcode is always shown too.
        private static string FailFastNote(ulong sub) => sub switch
        {
            2  => " = stack-cookie check failed",
            3  => " = corrupted list entry",
            8  => " = range check failed",
            10 => " = CFG indirect-call check failed",
            11 => " = CFG write check failed",
            _  => "",
        };
    }
}
