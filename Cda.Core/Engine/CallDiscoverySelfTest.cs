using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Cda.Core.Cpu;
using Cda.Core.Memory;
using Cda.Core.Model;
using Cda.Core.Pe;

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

            string? peFailure = VerifyPeMetadataDiscovery();
            if (peFailure != null) return peFailure;

            // Presentation must normalize an ASLR-adjusted live VA back to the
            // link-time address a static disassembler displays.
            var module = new ModuleInfo("sample.exe", 0x01000000, 0x00100000,
                preferredBaseAddress: 0x00400000);
            if (!module.TryToPreferredAddress(0x01036B35, out ulong preferred)
                || preferred != 0x00436B35)
                return $"FAIL: ASLR address normalized to 0x{preferred:X}.";

            return "PASS";
        }

        private static string? VerifyPeMetadataDiscovery()
        {
            const ulong PreferredBase = 0x00400000;
            const ulong LiveBase = 0x00600000;

            (byte[] file, byte[] mapped) = BuildX86ExportImage();
            var x86 = new X86Architecture();

            var fileFunctions = new List<TracedFunction>();
            var fileEdges = new List<(ulong Site, ulong Target)>();
            var fileSource = new BufferMemorySource(file, 0, is64Bit: false);
            CallSiteScanner.ScanFileImage(fileSource, PeImage.FromFile(file), x86,
                fileFunctions, fileEdges, maxEdges: 32);
            if (!HasEdge(fileEdges, PreferredBase + 0x1020, PreferredBase + 0x1030))
                return "FAIL: streaming x86 scan did not traverse an exported routine.";

            var liveFunctions = new List<TracedFunction>();
            var liveEdges = new List<(ulong Site, ulong Target)>();
            var liveSource = new BufferMemorySource(mapped, LiveBase, is64Bit: false);
            var module = new ModuleInfo("exports.dll", LiveBase, (ulong)mapped.Length);
            CallSiteScanner.ScanModule(liveSource, module, x86,
                liveFunctions, liveEdges, maxEdges: 32);
            if (!HasEdge(liveEdges, LiveBase + 0x1020, LiveBase + 0x1030))
                return "FAIL: live x86 scan did not traverse an exported routine.";

            byte[] malformedPdata = BuildMalformedPdataImage();
            var pdataFunctions = new List<TracedFunction>();
            var pdataEdges = new List<(ulong Site, ulong Target)>();
            var pdataSource = new BufferMemorySource(malformedPdata, 0, is64Bit: true);
            CallSiteScanner.ScanFileImage(pdataSource, PeImage.FromFile(malformedPdata),
                new X64Architecture(), pdataFunctions, pdataEdges, maxEdges: 32);
            if (!HasEdge(pdataEdges, PreferredBase + 0x1000, PreferredBase + 0x1020))
                return "FAIL: exception metadata consumed a record beyond .pdata.";

            return null;
        }

        private static bool HasEdge(
            IReadOnlyList<(ulong Site, ulong Target)> edges, ulong site, ulong target)
        {
            foreach (var edge in edges)
                if (edge.Site == site && edge.Target == target) return true;
            return false;
        }

        private static (byte[] File, byte[] Mapped) BuildX86ExportImage()
        {
            byte[] file = new byte[0x600];
            int sectionTable = InitializePe(file, PeMachine.I386, sectionCount: 2,
                entryPointRva: 0x1000, sizeOfImage: 0x3000);
            WriteSection(file, sectionTable, ".text", 0x100, 0x1000,
                rawSize: 0x200, rawPointer: 0x200, characteristics: 0x60000020);
            WriteSection(file, sectionTable + 40, ".edata", 0x100, 0x2000,
                rawSize: 0x200, rawPointer: 0x400, characteristics: 0x40000040);

            const int OptionalHeader = 0x98;
            WriteU32(file, OptionalHeader + 96, 0x2000); // export directory RVA
            WriteU32(file, OptionalHeader + 100, 0x100);

            file[0x200] = 0xC3; // section/entry-point fallback stops immediately
            file[0x220] = 0xE8; // exported RVA 0x1020 calls RVA 0x1030
            BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(0x221), 0x0B);
            file[0x225] = 0xC3;
            file[0x230] = 0xC3;

            WriteU32(file, 0x400 + 16, 1);      // ordinal base
            WriteU32(file, 0x400 + 20, 1);      // NumberOfFunctions
            WriteU32(file, 0x400 + 28, 0x2028); // AddressOfFunctions
            WriteU32(file, 0x428, 0x1020);

            byte[] mapped = new byte[0x3000];
            Array.Copy(file, 0, mapped, 0, 0x200);
            Array.Copy(file, 0x200, mapped, 0x1000, 0x200);
            Array.Copy(file, 0x400, mapped, 0x2000, 0x200);
            return (file, mapped);
        }

        private static byte[] BuildMalformedPdataImage()
        {
            byte[] file = new byte[0x60C];
            int sectionTable = InitializePe(file, PeMachine.Amd64, sectionCount: 3,
                entryPointRva: 0x1000, sizeOfImage: 0x4000);
            WriteSection(file, sectionTable, ".text", 0x100, 0x1000,
                rawSize: 0x200, rawPointer: 0x200, characteristics: 0x60000020);
            WriteSection(file, sectionTable + 40, ".pdata", 12, 0x2000,
                rawSize: 12, rawPointer: 0x400, characteristics: 0x40000040);
            WriteSection(file, sectionTable + 80, ".junk", 0x200, 0x3000,
                rawSize: 0x200, rawPointer: 0x40C, characteristics: 0x40000040);

            const int OptionalHeader = 0x98;
            int exceptionDirectory = OptionalHeader + 112 + 3 * 8;
            WriteU32(file, exceptionDirectory, 0x2000);
            WriteU32(file, exceptionDirectory + 4, 24); // overstates .pdata by one record

            file[0x200] = 0xE8; // entry RVA 0x1000 calls leaf RVA 0x1020
            BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(0x201), 0x1B);
            file[0x205] = 0xC3;
            file[0x220] = 0xC3;

            WriteU32(file, 0x400, 0x1000); // the only real .pdata record
            WriteU32(file, 0x404, 0x1006);
            WriteU32(file, 0x408, 0);

            // These bytes belong to the next section. If trusted as a second
            // RUNTIME_FUNCTION they incorrectly classify RVA 0x1020 as mid-body.
            WriteU32(file, 0x40C, 0x1010);
            WriteU32(file, 0x410, 0x1030);
            WriteU32(file, 0x414, 0);
            return file;
        }

        private static int InitializePe(
            byte[] image, PeMachine machine, ushort sectionCount,
            uint entryPointRva, uint sizeOfImage)
        {
            const int PeOffset = 0x80;
            const int CoffHeader = PeOffset + 4;
            const int OptionalHeader = CoffHeader + 20;
            bool is64Bit = machine == PeMachine.Amd64;
            ushort optionalSize = is64Bit ? (ushort)0xF0 : (ushort)0xE0;

            WriteU16(image, 0, 0x5A4D);
            WriteU32(image, 0x3C, PeOffset);
            WriteU32(image, PeOffset, 0x00004550);
            WriteU16(image, CoffHeader, (ushort)machine);
            WriteU16(image, CoffHeader + 2, sectionCount);
            WriteU16(image, CoffHeader + 16, optionalSize);

            WriteU16(image, OptionalHeader, is64Bit ? (ushort)0x20B : (ushort)0x10B);
            WriteU32(image, OptionalHeader + 16, entryPointRva);
            if (is64Bit) WriteU64(image, OptionalHeader + 24, 0x00400000);
            else WriteU32(image, OptionalHeader + 28, 0x00400000);
            WriteU32(image, OptionalHeader + 32, 0x1000); // SectionAlignment
            WriteU32(image, OptionalHeader + 36, 0x200);  // FileAlignment
            WriteU32(image, OptionalHeader + 56, sizeOfImage);
            WriteU32(image, OptionalHeader + 60, 0x200);  // SizeOfHeaders
            WriteU32(image, OptionalHeader + (is64Bit ? 108 : 92), 16);
            return OptionalHeader + optionalSize;
        }

        private static void WriteSection(
            byte[] image, int offset, string name, uint virtualSize, uint virtualAddress,
            uint rawSize, uint rawPointer, uint characteristics)
        {
            for (int i = 0; i < name.Length && i < 8; i++)
                image[offset + i] = (byte)name[i];
            WriteU32(image, offset + 8, virtualSize);
            WriteU32(image, offset + 12, virtualAddress);
            WriteU32(image, offset + 16, rawSize);
            WriteU32(image, offset + 20, rawPointer);
            WriteU32(image, offset + 36, characteristics);
        }

        private static void WriteU16(byte[] data, int offset, ushort value) =>
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(offset), value);

        private static void WriteU32(byte[] data, int offset, uint value) =>
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), value);

        private static void WriteU64(byte[] data, int offset, ulong value) =>
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(offset), value);

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
