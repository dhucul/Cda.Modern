using System.Collections.Generic;
using Cda.Core.Cpu;
using Cda.Core.Memory;
using Cda.Core.Model;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Deterministic regression check for direct-call discovery. A call whose
    /// target is its own fall-through address is an instruction-pointer idiom,
    /// not a function call, and must never create a synthetic function row.
    /// </summary>
    public static class CallDiscoverySelfTest
    {
        public static string Run()
        {
            const ulong Base = 0x1000;
            var arch = new X86Architecture();

            // call $+5 ; pop eax ; ret
            byte[] getIp = { 0xE8, 0, 0, 0, 0, 0x58, 0xC3 };
            var calls = new List<(ulong Site, ulong Target)>(arch.FindDirectCalls(getIp, Base));
            if (calls.Count != 0)
                return $"FAIL: call-to-next surfaced as 0x{calls[0].Target:X}.";

            calls = ScanReachable(getIp);
            if (calls.Count != 0)
                return "FAIL: reachable scanner surfaced call-to-next.";

            // A blind linear sweep sees the E8 bytes after this entry's ret as a
            // call. Reachability traversal must stop at the ret and ignore them.
            byte[] embeddedData =
            {
                0xC3,
                0xE8, 0x05, 0, 0, 0,
                0x90, 0x90, 0x90, 0x90, 0x90, 0xC3,
            };
            calls = ScanReachable(embeddedData);
            if (calls.Count != 0)
                return "FAIL: embedded data surfaced as a reachable call.";

            // A genuine relative call must still be reported.
            byte[] realCall = { 0xE8, 1, 0, 0, 0, 0x90, 0xC3 };
            calls = ScanReachable(realCall);
            if (calls.Count != 1 || calls[0].Site != Base || calls[0].Target != Base + 6)
                return "FAIL: genuine direct call was lost.";

            // A decoded operand outside the actual mapped/raw-backed region must
            // not become an edge or function row.
            byte[] beyondEof = { 0xE8, 0x20, 0, 0, 0, 0xC3 };
            calls = ScanReachable(beyondEof);
            if (calls.Count != 0)
                return "FAIL: target beyond the executable source was accepted.";

            // AMD64 leaf functions need no .pdata entry. A target outside all
            // known non-leaf bodies therefore remains a valid candidate.
            calls = ScanReachable(realCall,
                new HashSet<ulong> { Base },
                new[] { new AddressRange(Base, Base + 5) });
            if (calls.Count != 1 || calls[0].Target != Base + 6)
                return "FAIL: genuine AMD64 leaf target was rejected.";

            // But a target in the middle of a known .pdata body must be rejected.
            calls = ScanReachable(realCall,
                new HashSet<ulong> { Base },
                new[] { new AddressRange(Base, Base + 7) });
            if (calls.Count != 0)
                return "FAIL: mid-function x64 target was accepted.";

            // Presentation must normalize an ASLR-adjusted live VA back to the
            // link-time address a static disassembler displays.
            var module = new ModuleInfo("sample.exe", 0x01000000, 0x00100000,
                preferredBaseAddress: 0x00400000);
            if (!module.TryToPreferredAddress(0x01036B35, out ulong preferred)
                || preferred != 0x00436B35)
                return $"FAIL: ASLR address normalized to 0x{preferred:X}.";

            return "PASS";
        }

        private static List<(ulong Site, ulong Target)> ScanReachable(
            byte[] code, ISet<ulong>? knownEntries = null,
            IReadOnlyList<AddressRange>? knownBodies = null)
        {
            const ulong Base = 0x1000;
            var memory = new BufferMemorySource(code, Base, is64Bit: false);
            var regions = new[] { new ExecutableRegion(Base, Base, (ulong)code.Length) };
            return ReachableCallScanner.FindDirectCalls(
                memory, is64Bit: false, regions, new[] { Base }, maxEdges: 32,
                knownEntries, knownBodies);
        }
    }
}
