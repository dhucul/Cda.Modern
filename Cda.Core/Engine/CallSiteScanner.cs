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
    /// Static call-graph discovery over executable PE regions. Discovery follows
    /// reachable control flow from image/function entry seeds instead of linearly
    /// treating every byte in a code section as an instruction. This keeps embedded
    /// constants and jump tables from producing phantom function rows.
    /// </summary>
    public static class CallSiteScanner
    {
        private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        private const int MaxPdataBytes = 8 * 1024 * 1024;

        public static void ScanModule(
            IMemorySource memory, ModuleInfo module, ICpuArchitecture arch,
            ICollection<TracedFunction> functions, ICollection<(ulong Site, ulong Target)> edges,
            int maxEdges = 60000)
        {
            byte[] header = new byte[0x1000];
            if (memory.ReadMemory(module.BaseAddress, header) < 0x200) return;

            PeImage pe;
            try { pe = PeImage.FromMappedImage(header, module.BaseAddress); }
            catch { return; }
            module.PreferredBaseAddress = pe.PreferredImageBase;

            var regions = BuildLiveRegions(pe, module);
            var seeds = BuildSeeds(memory, pe, module.BaseAddress, regions,
                fileBacked: false, fileLength: 0, includeExports: false,
                out Amd64FunctionMap? knownFunctions);
            ScanReachable(memory, arch, module.BaseAddress, regions, seeds,
                knownFunctions, functions, edges, maxEdges,
                preferredBase: module.PreferredBaseAddress);
        }

        /// <summary>
        /// Static discovery over an on-disk file image held in a managed buffer.
        /// Virtual addresses are retained for results while each executable RVA is
        /// mapped to its real raw file bytes for decoding.
        /// </summary>
        public static void ScanFileImage(
            byte[] file, PeImage pe, ICpuArchitecture arch,
            ICollection<TracedFunction> functions, ICollection<(ulong Site, ulong Target)> edges,
            int maxEdges = 60000)
        {
            var memory = new BufferMemorySource(file, 0, arch.Is64Bit);
            var regions = BuildFileRegions(pe, (ulong)file.LongLength, maxBytesPerSection: 0);
            var seeds = BuildSeeds(memory, pe, pe.PreferredImageBase, regions,
                fileBacked: true, fileLength: (ulong)file.LongLength, includeExports: true,
                out Amd64FunctionMap? knownFunctions);
            ScanReachable(memory, arch, pe.PreferredImageBase, regions, seeds,
                knownFunctions, functions, edges, maxEdges,
                preferredBase: pe.PreferredImageBase);
        }

        /// <summary>
        /// Static discovery over an on-disk file read through an
        /// <see cref="IMemorySource"/> at file offsets. Regions are clipped to the
        /// source's actual length, so a malformed section cannot create a target
        /// beyond EOF. No whole-section managed allocation is required.
        /// </summary>
        public static void ScanFileImage(
            IMemorySource file, PeImage pe, ICpuArchitecture arch,
            ICollection<TracedFunction> functions, ICollection<(ulong Site, ulong Target)> edges,
            int maxEdges = 60000)
        {
            ulong fileLength = file.MaxAddress;
            var regions = BuildFileRegions(pe, fileLength, maxBytesPerSection: 0);
            var seeds = BuildSeeds(file, pe, pe.PreferredImageBase, regions,
                fileBacked: true, fileLength: fileLength, includeExports: false,
                out Amd64FunctionMap? knownFunctions);
            ScanReachable(file, arch, pe.PreferredImageBase, regions, seeds,
                knownFunctions, functions, edges, maxEdges,
                preferredBase: pe.PreferredImageBase);
        }

        private static void ScanReachable(
            IMemorySource memory, ICpuArchitecture arch, ulong moduleBase,
            IReadOnlyList<ExecutableRegion> regions, IReadOnlyList<ulong> seeds,
            Amd64FunctionMap? knownFunctions,
            ICollection<TracedFunction> functions, ICollection<(ulong Site, ulong Target)> edges,
            int maxEdges, ulong preferredBase)
        {
            int remaining = maxEdges - edges.Count;
            if (remaining <= 0 || regions.Count == 0 || seeds.Count == 0) return;

            var found = ReachableCallScanner.FindDirectCalls(
                memory, arch.Is64Bit, regions, seeds, remaining,
                knownFunctions?.Entries, knownFunctions?.Bodies);
            var seen = new HashSet<ulong>();
            foreach (var function in functions) seen.Add(function.Address);

            foreach (var edge in found)
            {
                edges.Add(edge);
                if (seen.Add(edge.Target))
                {
                    ulong displayAddress = preferredBase != 0 && edge.Target >= moduleBase
                        ? preferredBase + (edge.Target - moduleBase)
                        : edge.Target;
                    functions.Add(new TracedFunction(edge.Target, moduleBase,
                        displayAddress: displayAddress));
                }
            }
        }

        private static List<ExecutableRegion> BuildLiveRegions(PeImage pe, ModuleInfo module)
        {
            var regions = new List<ExecutableRegion>();
            foreach (var sec in pe.Sections)
            {
                if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;

                ulong length = sec.VirtualSize != 0 ? sec.VirtualSize : sec.RawSize;
                if (module.Size != 0)
                {
                    if (sec.VirtualAddress >= module.Size) continue;
                    length = Math.Min(length, module.Size - sec.VirtualAddress);
                }
                if (length == 0) continue;

                ulong va = module.BaseAddress + sec.VirtualAddress;
                regions.Add(new ExecutableRegion(va, va, length));
            }
            return regions;
        }

        private static List<ExecutableRegion> BuildFileRegions(
            PeImage pe, ulong fileLength, int maxBytesPerSection)
        {
            var regions = new List<ExecutableRegion>();
            ulong baseVa = pe.PreferredImageBase;

            foreach (var sec in pe.Sections)
            {
                if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
                if (sec.RawPointer == 0 || sec.RawPointer >= fileLength) continue;

                // VirtualSize excludes file-alignment padding; RawSize and the
                // actual EOF bound guarantee every mapped target has real bytes.
                ulong logical = sec.VirtualSize != 0
                    ? Math.Min((ulong)sec.VirtualSize, sec.RawSize)
                    : sec.RawSize;
                ulong available = fileLength - sec.RawPointer;
                ulong length = Math.Min(logical, available);
                if (maxBytesPerSection > 0)
                    length = Math.Min(length, (ulong)maxBytesPerSection);
                if (length == 0) continue;

                regions.Add(new ExecutableRegion(
                    baseVa + sec.VirtualAddress, sec.RawPointer, length));
            }
            return regions;
        }

        private static List<ulong> BuildSeeds(
            IMemorySource memory, PeImage pe, ulong imageBase,
            IReadOnlyList<ExecutableRegion> regions,
            bool fileBacked, ulong fileLength, bool includeExports,
            out Amd64FunctionMap? knownFunctions)
        {
            var seeds = new List<ulong>();
            if (pe.EntryPointRva != 0) seeds.Add(imageBase + pe.EntryPointRva);

            if (includeExports)
            {
                try
                {
                    foreach (var export in pe.ReadExports())
                        if (!export.IsForwarder && export.Rva != 0)
                            seeds.Add(imageBase + export.Rva);
                }
                catch { /* a corrupt/partial export table contributes no seeds */ }
            }

            knownFunctions = ReadAmd64FunctionMap(
                memory, pe, imageBase, fileBacked, fileLength);
            if (knownFunctions != null)
                seeds.AddRange(knownFunctions.Entries);

            // Fallback seed for x86/no-.pdata images and independent executable
            // sections. Traversal stops at the first control-flow boundary; this is
            // not the old whole-section linear sweep.
            foreach (var region in regions) seeds.Add(region.VirtualAddress);
            return seeds;
        }

        // AMD64's exception directory identifies non-leaf function bodies. It is
        // strong positive evidence, but not a complete allowlist: true leaf
        // functions require no unwind entry. Use starts as traversal seeds and
        // ranges only to reject a call into the middle of a known function body.
        private static Amd64FunctionMap? ReadAmd64FunctionMap(
            IMemorySource memory, PeImage pe, ulong imageBase,
            bool fileBacked, ulong fileLength)
        {
            if (pe.Machine != PeMachine.Amd64) return null;
            var (rva, declaredSize) = pe.GetDirectory(PeImage.DataDirectory.Exception);
            if (rva == 0 || declaredSize < 12) return null;

            ulong readAddress;
            ulong available;
            if (fileBacked)
            {
                if (!TryFileOffset(pe, rva, fileLength, out readAddress)) return null;
                available = fileLength - readAddress;
            }
            else
            {
                if (rva >= pe.SizeOfImage) return null;
                readAddress = imageBase + rva;
                available = pe.SizeOfImage - rva;
            }

            int size = (int)Math.Min(
                Math.Min((ulong)declaredSize, available), (ulong)MaxPdataBytes);
            if (size < 12) return null;

            byte[] table = new byte[size];
            int read = memory.ReadMemory(readAddress, table);
            if (read < 12) return null;

            var entries = new HashSet<ulong>();
            var bodies = new List<AddressRange>();
            int count = read / 12;
            for (int i = 0; i < count; i++)
            {
                int offset = i * 12;
                uint begin = BinaryPrimitives.ReadUInt32LittleEndian(table.AsSpan(offset));
                uint end = BinaryPrimitives.ReadUInt32LittleEndian(table.AsSpan(offset + 4));
                if (end > begin && end <= pe.SizeOfImage)
                {
                    entries.Add(imageBase + begin);
                    bodies.Add(new AddressRange(imageBase + begin, imageBase + end));
                }
            }
            if (entries.Count == 0) return null;

            bodies.Sort((a, b) => a.Start.CompareTo(b.Start));
            var merged = new List<AddressRange>(bodies.Count);
            foreach (var body in bodies)
            {
                if (merged.Count == 0 || body.Start > merged[merged.Count - 1].EndExclusive)
                {
                    merged.Add(body);
                    continue;
                }

                var prior = merged[merged.Count - 1];
                if (body.EndExclusive > prior.EndExclusive)
                    merged[merged.Count - 1] = new AddressRange(prior.Start, body.EndExclusive);
            }
            return new Amd64FunctionMap(entries, merged);
        }

        private static bool TryFileOffset(
            PeImage pe, uint rva, ulong fileLength, out ulong offset)
        {
            foreach (var sec in pe.Sections)
            {
                if (rva < sec.VirtualAddress) continue;
                ulong delta = (ulong)rva - sec.VirtualAddress;
                if (delta >= sec.RawSize) continue;
                offset = (ulong)sec.RawPointer + delta;
                return offset < fileLength;
            }

            uint firstSection = pe.Sections.Count > 0
                ? pe.Sections[0].VirtualAddress
                : pe.SizeOfImage;
            if (rva < firstSection && rva < fileLength)
            {
                offset = rva;
                return true;
            }

            offset = 0;
            return false;
        }

        private sealed class Amd64FunctionMap
        {
            public readonly HashSet<ulong> Entries;
            public readonly List<AddressRange> Bodies;

            public Amd64FunctionMap(HashSet<ulong> entries, List<AddressRange> bodies)
            {
                Entries = entries;
                Bodies = bodies;
            }
        }
    }
}
