using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Cda.Core.Memory;
using Cda.Core.Model;
using Cda.Core.Pe;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Decides whether a candidate address is a <b>safe function entry</b> to splice.
    ///
    /// Discovery (<see cref="CallSiteScanner"/>) rejects unreachable/data decodes
    /// and obvious position-independent-code idioms, but a reachable call target is
    /// still not always a safe splice entry: alternate/mid-function entry points and
    /// unusual thunks can remain. Splicing an entry detour into one of those corrupts
    /// the target's code or control flow and crashes it — and only on the subset of
    /// binaries that contain such patterns, which is exactly the "some programs,
    /// not all" failure this guards against.
    ///
    /// Strategy, strongest signal first:
    ///   * <b>x64 with an exception table (.pdata)</b>: a RUNTIME_FUNCTION begin is
    ///     a known entry and its [Begin, End) extent bounds the splice. A candidate
    ///     inside such a body but not at its begin is rejected. A candidate outside
    ///     all known bodies remains eligible because leaf functions need no unwind
    ///     metadata.
    ///   * <b>otherwise</b> (x86, a leaf function, a module with no .pdata, or a
    ///     module not yet enumerable at a frozen debug event): reject the
    ///     unambiguous "call to the next instruction" PIC idiom and clamp the steal
    ///     length to the next candidate, known function, or module boundary.
    ///
    /// All reads are host-side (ReadProcessMemory); nothing is written here. The
    /// guard is lazy and caches its per-module parse.
    /// </summary>
    internal sealed class EntryPointGuard
    {
        private readonly IMemorySource _memory;
        private readonly ModuleMap _modules;
        private readonly bool _x64;                 // true => the target is true AMD64
        private readonly ulong[] _sortedCandidates; // for the fallback next-entry clamp
        private readonly Dictionary<ulong, ModuleEntries> _byModule = new();

        public EntryPointGuard(IMemorySource memory, ModuleMap modules, bool isX64,
            IReadOnlyCollection<ulong> candidates)
        {
            _memory = memory;
            _modules = modules;
            _x64 = isX64;
            var c = new List<ulong>(candidates);
            c.Sort();
            _sortedCandidates = c.ToArray();
        }

        /// <summary>
        /// True if <paramref name="address"/> is safe to hook. On success
        /// <paramref name="maxPatchLen"/> bounds how many bytes the splice may
        /// overwrite (so it cannot run past the function into its neighbour). On
        /// failure <paramref name="reason"/> explains the skip.
        /// </summary>
        public bool IsHookable(ulong address, out int maxPatchLen, out string? reason)
        {
            maxPatchLen = int.MaxValue;
            reason = null;

            var module = _modules.Resolve(address);
            int knownFunctionBoundary = int.MaxValue;
            if (module != null)
            {
                var entries = GetModuleEntries(module);
                if (entries.HasFunctionTable)
                {
                    ulong rva64 = address - module.BaseAddress;
                    if (rva64 <= uint.MaxValue)
                    {
                        uint rva = (uint)rva64;
                        if (entries.Extent.TryGetValue(rva, out uint extent))
                        {
                            if (extent > 0 && extent < int.MaxValue) maxPatchLen = (int)extent;
                            return true;
                        }

                        // AMD64 leaf functions do not require unwind metadata.
                        // Reject only a target proven to be inside a known body.
                        if (entries.ContainsKnownBody(rva))
                        {
                            reason = "Falls inside a .pdata function body but is not its entry.";
                            return false;
                        }
                        knownFunctionBoundary = entries.GapToNextKnownEntry(rva);
                    }
                }
            }

            // Fallback path (x86, a module with no exception table, or a module not
            // yet enumerable at a frozen debug event): reject only the unambiguous
            // call-to-next PIC idiom, and clamp the steal to the next candidate.
            if (IsCallToNextIdiom(address))
            {
                reason = "Target is a call-to-next (PIC EIP/RIP thunk), not a function entry.";
                return false;
            }
            maxPatchLen = Math.Min(GapToNextCandidate(address), knownFunctionBoundary);
            if (module != null)
                maxPatchLen = Math.Min(maxPatchLen, GapToModuleEnd(module, address));
            return true;
        }

        private ModuleEntries GetModuleEntries(ModuleInfo module)
        {
            if (_byModule.TryGetValue(module.BaseAddress, out var cached)) return cached;
            var e = ParseModule(module);
            _byModule[module.BaseAddress] = e;
            return e;
        }

        // Parse the module's exception directory into an entry-RVA -> byte-extent
        // map. Only the AMD64 .pdata has the 12-byte RUNTIME_FUNCTION layout read
        // below; x86 has none and ARM64 differs, so both take the fallback path.
        private ModuleEntries ParseModule(ModuleInfo module)
        {
            var result = new ModuleEntries();
            try
            {
                byte[] header = new byte[0x1000];
                if (_memory.ReadMemory(module.BaseAddress, header) < 0x200) return result;
                var pe = PeImage.FromMappedImage(header, module.BaseAddress);
                if (!_x64 || !pe.Is64Bit) return result;

                var (pdataRva, pdataSize) = pe.GetDirectory(PeImage.DataDirectory.Exception);
                if (pdataRva == 0 || pdataSize == 0) return result;

                const uint MaxPdataBytes = 8u * 1024 * 1024;
                int size = (int)Math.Min(pdataSize, MaxPdataBytes);
                byte[] pdata = new byte[size];
                int read = _memory.ReadMemory(module.BaseAddress + pdataRva, pdata);
                // A short/failed read must NOT zero out coverage: leave the table
                // absent so the fallback path applies instead of rejecting all.
                if (read < 12) return result;

                int count = read / 12;
                var extent = new Dictionary<uint, uint>(count);
                var bodies = new List<RvaRange>(count);
                for (int i = 0; i < count; i++)
                {
                    uint begin = BinaryPrimitives.ReadUInt32LittleEndian(pdata.AsSpan(i * 12));
                    uint end = BinaryPrimitives.ReadUInt32LittleEndian(pdata.AsSpan(i * 12 + 4));
                    // Keep the first range seen for a begin RVA; skip degenerate
                    // entries. (Secondary/chained chunks of a split function are not
                    // direct-call targets in practice, so they never reach this map
                    // from discovery and need no special handling.)
                    if (end > begin && end <= pe.SizeOfImage)
                    {
                        if (!extent.ContainsKey(begin)) extent[begin] = end - begin;
                        bodies.Add(new RvaRange(begin, end));
                    }
                }
                if (extent.Count > 0)
                {
                    result.HasFunctionTable = true;
                    result.Extent = extent;
                    result.SetBodies(bodies);
                }
            }
            catch
            {
                // Any parse/read failure leaves HasFunctionTable false so the
                // fallback path applies — never a hard reject of the whole module.
            }
            return result;
        }

        // 5-byte "call $+5" (E8 00 00 00 00) ending exactly at <address>: the
        // classic EIP/RIP thunk whose "target" is the following instruction, never
        // a real function entry. Reads are read-only; a failed read is treated as
        // "not the idiom" so we never reject on a benign read miss.
        private bool IsCallToNextIdiom(ulong address)
        {
            if (address < 5) return false;
            Span<byte> b = stackalloc byte[5];
            if (_memory.ReadMemory(address - 5, b) != 5) return false;
            return b[0] == 0xE8 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0;
        }

        private int GapToNextCandidate(ulong address)
        {
            int i = Array.BinarySearch(_sortedCandidates, address);
            i = i < 0 ? ~i : i + 1; // first candidate strictly greater than address
            if (i < _sortedCandidates.Length)
            {
                ulong gap = _sortedCandidates[i] - address;
                if (gap > 0 && gap < int.MaxValue) return (int)gap;
            }
            return int.MaxValue;
        }

        private static int GapToModuleEnd(ModuleInfo module, ulong address)
        {
            if (module.Size == 0 || address < module.BaseAddress) return int.MaxValue;
            ulong offset = address - module.BaseAddress;
            if (offset >= module.Size) return 0;
            ulong gap = module.Size - offset;
            return gap < int.MaxValue ? (int)gap : int.MaxValue;
        }

        private readonly struct RvaRange
        {
            public readonly uint Start;
            public readonly uint EndExclusive;

            public RvaRange(uint start, uint endExclusive)
            {
                Start = start;
                EndExclusive = endExclusive;
            }

            public bool Contains(uint rva) => rva >= Start && rva < EndExclusive;
        }

        private sealed class ModuleEntries
        {
            public bool HasFunctionTable;
            public Dictionary<uint, uint> Extent = new(); // entry RVA -> byte extent
            private uint[] _sortedBegins = Array.Empty<uint>();
            private RvaRange[] _bodies = Array.Empty<RvaRange>();

            public void SetBodies(List<RvaRange> bodies)
            {
                _sortedBegins = new uint[Extent.Count];
                Extent.Keys.CopyTo(_sortedBegins, 0);
                Array.Sort(_sortedBegins);

                bodies.Sort((a, b) => a.Start.CompareTo(b.Start));
                var merged = new List<RvaRange>(bodies.Count);
                foreach (var body in bodies)
                {
                    if (merged.Count == 0 || body.Start > merged[merged.Count - 1].EndExclusive)
                    {
                        merged.Add(body);
                        continue;
                    }

                    var prior = merged[merged.Count - 1];
                    if (body.EndExclusive > prior.EndExclusive)
                        merged[merged.Count - 1] = new RvaRange(prior.Start, body.EndExclusive);
                }
                _bodies = merged.ToArray();
            }

            public bool ContainsKnownBody(uint rva)
            {
                int lo = 0, hi = _bodies.Length - 1;
                while (lo <= hi)
                {
                    int mid = lo + ((hi - lo) >> 1);
                    var body = _bodies[mid];
                    if (rva < body.Start) hi = mid - 1;
                    else if (body.Contains(rva)) return true;
                    else lo = mid + 1;
                }
                return false;
            }

            public int GapToNextKnownEntry(uint rva)
            {
                int i = Array.BinarySearch(_sortedBegins, rva);
                i = i < 0 ? ~i : i + 1;
                if (i >= _sortedBegins.Length) return int.MaxValue;
                uint gap = _sortedBegins[i] - rva;
                return gap < int.MaxValue ? (int)gap : int.MaxValue;
            }
        }
    }
}
