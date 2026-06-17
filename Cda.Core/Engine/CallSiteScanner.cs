using System;
using System.Collections.Generic;
using Cda.Core.Cpu;
using Cda.Core.Memory;
using Cda.Core.Model;
using Cda.Core.Pe;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Static call-graph discovery over a live (memory-mapped) module: read each
    /// executable section, decode it, and collect direct call sites and their
    /// targets. This is the safe, read-only counterpart to the legacy discovery
    /// pass — it touches nothing in the target, it only reads.
    ///
    /// The result is expressed as a <see cref="TraceDataset"/> so it flows
    /// straight into the existing visualization: discovered functions become
    /// nodes and discovered call sites become edges.
    /// </summary>
    public static class CallSiteScanner
    {
        private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        private const int MaxSectionBytes = 8 * 1024 * 1024;

        public static void ScanModule(
            IMemorySource memory, ModuleInfo module, ICpuArchitecture arch,
            ICollection<TracedFunction> functions, ICollection<(ulong Site, ulong Target)> edges,
            int maxEdges = 60000)
        {
            // Read the headers to find the section table (first page is enough).
            byte[] header = new byte[0x1000];
            if (memory.ReadMemory(module.BaseAddress, header) < 0x200) return;

            PeImage pe;
            try { pe = PeImage.FromMappedImage(header, module.BaseAddress); }
            catch { return; }

            ulong moduleEnd = module.BaseAddress + Math.Max(module.Size, pe.SizeOfImage);
            var seenTargets = new HashSet<ulong>();

            foreach (var sec in pe.Sections)
            {
                if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;

                // For a mapped image use VirtualSize: that is the extent actually
                // committed in memory. RawSize is a file-layout figure and can run
                // past the committed pages, which makes one big read fail outright.
                uint vsize = sec.VirtualSize != 0 ? sec.VirtualSize : sec.RawSize;
                int size = (int)Math.Min(vsize, (uint)MaxSectionBytes);
                if (size <= 0) continue;

                ulong secBase = module.BaseAddress + sec.VirtualAddress;

                // Read in chunks so an unreadable page (guard page, partial commit)
                // skips just that chunk instead of failing the whole section.
                const int chunk = 0x10000;
                for (int off = 0; off < size; off += chunk)
                {
                    int len = Math.Min(chunk, size - off);
                    byte[] code = new byte[len];
                    int read = memory.ReadMemory(secBase + (ulong)off, code);
                    if (read <= 0) continue;
                    if (read < len) Array.Resize(ref code, read);

                    foreach (var (site, target) in arch.FindDirectCalls(code, secBase + (ulong)off))
                    {
                        // Keep only intra-module targets so every edge resolves to a node.
                        if (target < module.BaseAddress || target >= moduleEnd) continue;

                        edges.Add((site, target));
                        if (seenTargets.Add(target))
                            functions.Add(new TracedFunction(target, module.BaseAddress));

                        if (edges.Count >= maxEdges) return;
                    }
                }
            }
        }

        /// <summary>
        /// Static discovery over an on-disk file image (uses file offsets, not a
        /// mapped layout). This is what lets "Open module" populate the function
        /// list for executables, which usually export nothing.
        /// </summary>
        public static void ScanFileImage(
            byte[] file, PeImage pe, ICpuArchitecture arch,
            ICollection<TracedFunction> functions, ICollection<(ulong Site, ulong Target)> edges,
            int maxEdges = 60000)
        {
            ulong baseVa = pe.PreferredImageBase;
            ulong moduleEnd = baseVa + pe.SizeOfImage;
            var seen = new HashSet<ulong>();

            foreach (var sec in pe.Sections)
            {
                if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;

                int start = (int)sec.RawPointer;
                int len = (int)Math.Min(sec.RawSize, (uint)MaxSectionBytes);
                if (start <= 0 || len <= 0 || start >= file.Length) continue;
                len = Math.Min(len, file.Length - start);

                byte[] code = new byte[len];
                Array.Copy(file, start, code, 0, len);
                ulong codeBase = baseVa + sec.VirtualAddress;

                foreach (var (site, target) in arch.FindDirectCalls(code, codeBase))
                {
                    if (target < baseVa || target >= moduleEnd) continue;
                    edges.Add((site, target));
                    if (seen.Add(target))
                        functions.Add(new TracedFunction(target, baseVa));
                    if (edges.Count >= maxEdges) return;
                }
            }
        }

        /// <summary>
        /// Static discovery over an on-disk file whose bytes are read through an
        /// <see cref="IMemorySource"/> at <b>file offsets</b> (e.g. a
        /// <c>MappedFileMemorySource</c>) instead of a managed <c>byte[]</c>. The
        /// decoder pulls each executable section's bytes on demand and in full — there
        /// is no per-section byte cap here, because nothing is materialized: a section
        /// of any size streams through with flat memory use. The only bound on the work
        /// is <paramref name="maxEdges"/>. This is the file-source counterpart of
        /// "Open module" for files too large to slurp; <paramref name="pe"/> need only
        /// be parsed from the headers (the section table), its body bytes untouched.
        /// </summary>
        public static void ScanFileImage(
            IMemorySource file, PeImage pe, ICpuArchitecture arch,
            ICollection<TracedFunction> functions, ICollection<(ulong Site, ulong Target)> edges,
            int maxEdges = 60000)
        {
            ulong baseVa = pe.PreferredImageBase;
            ulong moduleEnd = baseVa + pe.SizeOfImage;
            long fileLen = (long)file.MaxAddress;
            var seen = new HashSet<ulong>();

            foreach (var sec in pe.Sections)
            {
                if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;

                long start = sec.RawPointer;
                long len = sec.RawSize;
                if (start <= 0 || len <= 0 || start >= fileLen) continue;
                len = Math.Min(len, fileLen - start);
                ulong codeBase = baseVa + sec.VirtualAddress;

                // Stream the whole section through the decoder (no copy, no 8 MB cap):
                // a large .text is covered end-to-end, bounded only by maxEdges.
                foreach (var (site, target) in arch.FindDirectCalls(file, (ulong)start, len, codeBase))
                {
                    if (target < baseVa || target >= moduleEnd) continue;
                    edges.Add((site, target));
                    if (seen.Add(target))
                        functions.Add(new TracedFunction(target, baseVa));
                    if (edges.Count >= maxEdges) return;
                }
            }
        }
    }
}
