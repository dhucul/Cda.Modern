using System;
using System.Collections.Generic;
using System.Text;
using Iced.Intel;
using Cda.Core.Memory;
using Cda.Core.Model;
using Cda.Core.Pe;

namespace Cda.Core.Engine
{
    /// <summary>Encoding a discovered string was stored in.</summary>
    public enum StringKind { Ascii, Utf16 }

    /// <summary>
    /// A printable string found in a module's data, together with the functions
    /// in that module that reference it. The cross-references are what let the UI
    /// jump from a string straight to the code that uses it.
    /// </summary>
    public sealed class ExtractedString
    {
        /// <summary>VA of the string's first byte (in the same base as the functions passed in).</summary>
        public ulong Address;

        /// <summary>The decoded text (printable characters only).</summary>
        public string Text = "";

        public StringKind Kind;

        /// <summary>Bytes the string occupies, excluding the terminator (chars*2 for UTF-16).</summary>
        public int ByteLength;

        /// <summary>Name of the section the string lives in (e.g. <c>.rdata</c>).</summary>
        public string Section = "";

        /// <summary>
        /// Entry addresses of the discovered functions that reference this string,
        /// in first-seen order. Empty when nothing in the scanned code points at it
        /// (e.g. a resource string loaded by API rather than by address).
        /// </summary>
        public List<ulong> ReferencedBy = new();

        /// <summary>Total referencing instructions (≥ <see cref="ReferencedBy"/> count when a function refers more than once).</summary>
        public int RefSites;
    }

    /// <summary>
    /// Pulls the printable strings out of a PE's data sections and resolves, for
    /// each one, which discovered functions load its address — i.e. a Strings view
    /// with code cross-references, the analogue of the same feature in IDA/Ghidra.
    ///
    /// Two entry points share the same core: <see cref="Scan"/> works over an
    /// on-disk file image (preferred-base space; the caller rebases), while
    /// <see cref="ScanModule"/> works over a module already mapped into a live
    /// process (absolute addresses, read through an <see cref="IMemorySource"/>).
    /// </summary>
    public static class StringScanner
    {
        private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        private const int MaxSectionBytes = 32 * 1024 * 1024;
        private const int Chunk = 0x10000; // read mapped sections in pages so one bad page skips only itself

        /// <summary>
        /// Extract strings from an on-disk <paramref name="file"/> image and
        /// attribute their code references to <paramref name="functions"/>
        /// (discovered entry points, in the image's preferred-base space).
        /// </summary>
        /// <param name="minLength">Shortest run of printable characters kept (default 4).</param>
        /// <param name="maxStrings">Hard cap so a giant resource blob can't run away.</param>
        public static List<ExtractedString> Scan(
            byte[] file, PeImage pe,
            IReadOnlyList<TracedFunction> functions,
            int minLength = 4, int maxStrings = 200000)
        {
            ulong baseVa = pe.PreferredImageBase;
            var strings = new List<ExtractedString>();

            bool capped = false;
            foreach (var sec in pe.Sections)
            {
                if (capped) break;
                int start = (int)sec.RawPointer;
                if (start <= 0 || start >= file.Length) continue;
                uint vsize = sec.VirtualSize != 0 ? sec.VirtualSize : sec.RawSize;
                long avail = Math.Min(Math.Min((long)sec.RawSize, vsize), (long)MaxSectionBytes);
                int len = (int)Math.Min(avail, file.Length - start);
                if (len <= 0) continue;
                capped = FindStringRuns(file, start, len, baseVa + sec.VirtualAddress, sec.Name,
                                        minLength, maxStrings, strings);
            }
            if (strings.Count == 0) return strings;

            var (starts, ends, entries, refSets) = BuildIndex(strings, functions);
            int bitness = pe.Is64Bit ? 64 : 32;

            foreach (var sec in pe.Sections)
            {
                if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
                int start = (int)sec.RawPointer;
                int len = (int)Math.Min(sec.RawSize, (uint)MaxSectionBytes);
                if (start <= 0 || len <= 0 || start >= file.Length) continue;
                len = Math.Min(len, file.Length - start);

                byte[] code = new byte[len];
                Array.Copy(file, start, code, 0, len);
                AttributeRefsInCode(code, len, baseVa + sec.VirtualAddress, bitness,
                                    starts, ends, entries, strings, refSets);
            }
            return strings;
        }

        /// <summary>
        /// Extract strings from a module already mapped into a live process, reading
        /// through <paramref name="memory"/> (e.g. ReadProcessMemory) and attributing
        /// references to <paramref name="functions"/>. Addresses are absolute (the
        /// module's actual load base), so no rebasing is needed. Used by "Attach to
        /// process", where there is no on-disk buffer to scan.
        /// </summary>
        public static List<ExtractedString> ScanModule(
            IMemorySource memory, ModuleInfo module,
            IReadOnlyList<TracedFunction> functions,
            int minLength = 4, int maxStrings = 200000)
        {
            var strings = new List<ExtractedString>();

            // The first page carries the headers + section table; parse the mapped
            // image (RVA == offset) to find the sections.
            byte[] header = new byte[0x1000];
            if (memory.ReadMemory(module.BaseAddress, header) < 0x200) return strings;
            PeImage pe;
            try { pe = PeImage.FromMappedImage(header, module.BaseAddress); }
            catch { return strings; }

            int bitness = pe.Is64Bit ? 64 : 32;
            ulong moduleEnd = module.BaseAddress + Math.Max(module.Size, pe.SizeOfImage);

            // (1) strings from every section with committed pages — including
            // executable ones (compilers park read-only literals in .text), matching
            // the on-disk Scan so the same module yields the same strings either way.
            bool capped = false;
            foreach (var sec in pe.Sections)
            {
                if (capped) break;
                if (!ForEachReadableChunk(memory, module.BaseAddress, moduleEnd, sec,
                        (data, read, chunkVa) =>
                            FindStringRuns(data, 0, read, chunkVa, sec.Name, minLength, maxStrings, strings)))
                    capped = true;
            }
            // No functions to attribute to (e.g. an app DLL we list for its strings
            // but don't cross-reference) — skip the disassembly pass entirely.
            if (strings.Count == 0 || functions.Count == 0) return strings;

            var (starts, ends, entries, refSets) = BuildIndex(strings, functions);

            // (2) references from every executable section.
            foreach (var sec in pe.Sections)
            {
                if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
                ForEachReadableChunk(memory, module.BaseAddress, moduleEnd, sec,
                    (data, read, chunkVa) =>
                    {
                        AttributeRefsInCode(data, read, chunkVa, bitness, starts, ends, entries, strings, refSets);
                        return false; // never "capped" for the reference pass
                    });
            }
            return strings;
        }

        // Read a mapped section in page-sized chunks, invoking <paramref name="onChunk"/>
        // with each readable chunk's bytes, length, and base VA. Returns false as soon
        // as a chunk callback returns true ("capped"), else true.
        private static bool ForEachReadableChunk(
            IMemorySource memory, ulong moduleBase, ulong moduleEnd, PeSection sec,
            Func<byte[], int, ulong, bool> onChunk)
        {
            uint vsize = sec.VirtualSize != 0 ? sec.VirtualSize : sec.RawSize;
            int len = (int)Math.Min(vsize, (uint)MaxSectionBytes);
            if (len <= 0) return true;
            ulong secVa = moduleBase + sec.VirtualAddress;
            if (secVa >= moduleEnd) return true;
            // Never read past the module — a malformed/crafted PE could declare a
            // section running off the end, which would pull adjacent memory in.
            ulong avail = moduleEnd - secVa;
            if ((ulong)len > avail) len = (int)Math.Min(avail, int.MaxValue);

            // Whole-section read first: a fully-committed section (the usual case for
            // .rdata/.rsrc, where the strings live) comes back in one piece, so no
            // string is ever split across a chunk boundary — however long it is.
            // ReadMemory returns 0 if the range crosses an uncommitted page, in which
            // case we fall back to page-sized chunks (e.g. .data with a .bss tail).
            byte[] whole = new byte[len];
            if (memory.ReadMemory(secVa, whole) == len)
                return !onChunk(whole, len, secVa);

            byte[] buf = new byte[Chunk];
            for (int off = 0; off < len; off += Chunk)
            {
                int clen = Math.Min(Chunk, len - off);
                ulong chunkVa = secVa + (ulong)off;
                if (chunkVa >= moduleEnd) break;
                int read = memory.ReadMemory(chunkVa, buf.AsSpan(0, clen));
                if (read <= 0) continue; // unreadable page — skip just this chunk
                if (onChunk(buf, read, chunkVa)) return false;
            }
            return true;
        }

        // --- shared core -----------------------------------------------------

        // Sort the strings and build the interval index (for address → string) plus
        // the sorted function-entry table (for flooring a reference to its function).
        private static (ulong[] starts, ulong[] ends, ulong[] entries, HashSet<ulong>?[] refSets)
            BuildIndex(List<ExtractedString> strings, IReadOnlyList<TracedFunction> functions)
        {
            strings.Sort(static (a, b) => a.Address.CompareTo(b.Address));
            int n = strings.Count;
            var starts = new ulong[n];
            var ends = new ulong[n];
            for (int i = 0; i < n; i++)
            {
                starts[i] = strings[i].Address;
                ends[i] = strings[i].Address + (ulong)Math.Max(1, strings[i].ByteLength);
            }
            var entries = new ulong[functions.Count];
            for (int i = 0; i < functions.Count; i++) entries[i] = functions[i].Address;
            Array.Sort(entries);
            return (starts, ends, entries, new HashSet<ulong>?[n]);
        }

        // Scan data[from .. from+len) for ASCII + UTF-16 strings; the VA of data[from]
        // is vaBase. Returns true if the maxStrings cap was reached (caller stops).
        private static bool FindStringRuns(
            byte[] data, int from, int len, ulong vaBase, string section,
            int minLength, int maxStrings, List<ExtractedString> result)
        {
            int end = from + len;

            // ASCII runs that end in a NUL terminator (a C string). The NUL is what
            // separates real strings from code: a run of printable code bytes in a
            // .text section is almost never followed by a 0x00, so requiring the
            // terminator drops that junk while keeping genuine literals (which the
            // compiler always NUL-terminates) wherever they live — .rdata or .text.
            // A UTF-16 string's interleaved zero bytes break it into length-1 runs
            // here, so this pass never double-counts wide strings.
            int i = from;
            while (i < end)
            {
                if (!IsPrintable(data[i])) { i++; continue; }
                int j = i;
                while (j < end && IsPrintable(data[j])) j++;
                int runLen = j - i;
                if (runLen >= minLength && j < end && data[j] == 0)
                {
                    result.Add(new ExtractedString
                    {
                        Address = vaBase + (ulong)(i - from),
                        Text = Latin1(data, i, runLen),
                        Kind = StringKind.Ascii,
                        ByteLength = runLen,
                        Section = section,
                    });
                    if (result.Count >= maxStrings) return true;
                }
                i = j;
            }

            // UTF-16LE runs (printable low byte, zero high byte). Don't begin a wide
            // run in the tail of an ASCII run — the last ASCII char plus its NUL
            // terminator would masquerade as the first wide char — which also keeps
            // the ASCII and UTF-16 intervals strictly disjoint for the lookup index.
            i = from;
            while (i + 1 < end)
            {
                if (i > from && IsPrintable(data[i - 1])) { i++; continue; }
                if (!(IsPrintable(data[i]) && data[i + 1] == 0)) { i++; continue; }
                int j = i; int chars = 0;
                while (j + 1 < end && IsPrintable(data[j]) && data[j + 1] == 0) { j += 2; chars++; }
                if (chars >= minLength)
                {
                    var sb = new StringBuilder(chars);
                    for (int k = i; k < i + chars * 2; k += 2) sb.Append((char)data[k]);
                    result.Add(new ExtractedString
                    {
                        Address = vaBase + (ulong)(i - from),
                        Text = sb.ToString(),
                        Kind = StringKind.Utf16,
                        ByteLength = chars * 2,
                        Section = section,
                    });
                    if (result.Count >= maxStrings) return true;
                }
                i = Math.Max(j, i + 1);
            }
            return false;
        }

        // Decode code[0 .. codeLen) at base VA codeBase and attribute every absolute /
        // RIP-relative data reference that lands in a string to the enclosing function.
        private static void AttributeRefsInCode(
            byte[] code, int codeLen, ulong codeBase, int bitness,
            ulong[] starts, ulong[] ends, ulong[] entries,
            List<ExtractedString> strings, HashSet<ulong>?[] refSets)
        {
            var reader = new ByteArrayCodeReader(code, 0, codeLen);
            var decoder = Iced.Intel.Decoder.Create(bitness, reader, codeBase, DecoderOptions.None);

            while (reader.CanReadByte)
            {
                decoder.Decode(out Instruction instr);
                if (instr.Code == Code.INVALID) continue;

                int opCount = instr.OpCount;
                for (int op = 0; op < opCount; op++)
                {
                    if (!TryReferencedAddress(instr, op, out ulong addr)) continue;

                    int si = FindString(starts, ends, addr);
                    if (si < 0) continue;

                    strings[si].RefSites++;
                    ulong fn = FloorEntry(entries, instr.IP);
                    if (fn == 0) continue;

                    var set = refSets[si] ??= new HashSet<ulong>();
                    if (set.Add(fn)) strings[si].ReferencedBy.Add(fn);
                }
            }
        }

        // The address an operand points at, when it's a plain absolute or
        // RIP-relative data reference (the forms that load a string's address).
        // Stack/based memory ([rsp+x], [rbp+x], indexed) is ignored — it can't be a
        // static string pointer.
        private static bool TryReferencedAddress(in Instruction instr, int op, out ulong addr)
        {
            addr = 0;
            switch (instr.GetOpKind(op))
            {
                case OpKind.Memory:
                    if (instr.IsIPRelativeMemoryOperand)
                    {
                        addr = instr.IPRelativeMemoryAddress;
                        return true;
                    }
                    if (instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None)
                    {
                        addr = instr.MemoryDisplacement64;
                        return true;
                    }
                    return false;

                // x86 "push offset aString" / "mov reg, offset aString".
                case OpKind.Immediate32:
                    addr = instr.Immediate32;
                    return true;
                case OpKind.Immediate64:
                    addr = instr.Immediate64;
                    return true;
                case OpKind.Immediate32to64:
                    long v = instr.Immediate32to64;
                    if (v <= 0) return false;
                    addr = (ulong)v;
                    return true;

                default:
                    return false;
            }
        }

        // Largest i with starts[i] <= addr, then bound-check against ends[i].
        private static int FindString(ulong[] starts, ulong[] ends, ulong addr)
        {
            int lo = 0, hi = starts.Length - 1, res = -1;
            while (lo <= hi)
            {
                int mid = (int)(((uint)lo + (uint)hi) >> 1);
                if (starts[mid] <= addr) { res = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            return res >= 0 && addr < ends[res] ? res : -1;
        }

        // Enclosing function entry for an instruction address (largest entry <= ip),
        // or 0 if the address sits below the first known function.
        private static ulong FloorEntry(ulong[] entries, ulong ip)
        {
            int lo = 0, hi = entries.Length - 1, res = -1;
            while (lo <= hi)
            {
                int mid = (int)(((uint)lo + (uint)hi) >> 1);
                if (entries[mid] <= ip) { res = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            return res >= 0 ? entries[res] : 0;
        }

        private static bool IsPrintable(byte b) => b >= 0x20 && b <= 0x7E;

        private static string Latin1(byte[] data, int off, int len)
        {
            var sb = new StringBuilder(len);
            for (int i = 0; i < len; i++) sb.Append((char)data[off + i]);
            return sb.ToString();
        }
    }
}
