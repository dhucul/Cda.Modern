using System;
using System.Collections.Generic;
using Cda.Core.Memory;
using Iced.Intel;

namespace Cda.Core.Cpu
{
    /// <summary>
    /// Maps one executable virtual-address range to the address used by its byte
    /// source (the same VA for a live process, a raw file offset for a PE file).
    /// Length is always clipped to bytes that actually exist in that source.
    /// </summary>
    internal readonly struct ExecutableRegion
    {
        public readonly ulong VirtualAddress;
        public readonly ulong ReadAddress;
        public readonly ulong Length;

        public ExecutableRegion(ulong virtualAddress, ulong readAddress, ulong length)
        {
            VirtualAddress = virtualAddress;
            ReadAddress = readAddress;
            Length = length;
        }

        public bool Contains(ulong address) =>
            address >= VirtualAddress && address - VirtualAddress < Length;
    }

    /// <summary>A half-open virtual-address range used to classify known function bodies.</summary>
    internal readonly struct AddressRange
    {
        public readonly ulong Start;
        public readonly ulong EndExclusive;

        public AddressRange(ulong start, ulong endExclusive)
        {
            Start = start;
            EndExclusive = endExclusive;
        }

        public bool Contains(ulong address) => address >= Start && address < EndExclusive;
    }

    /// <summary>
    /// Recursive control-flow discovery over executable regions. Unlike a linear
    /// sweep, this decodes only instructions reachable from known entry seeds and
    /// follows direct calls/branches. Embedded constants and jump-table bytes are
    /// therefore not reinterpreted as call instructions and cannot create phantom
    /// function rows.
    /// </summary>
    internal static class ReachableCallScanner
    {
        private const int ReadWindow = 64 * 1024;
        private const int MaxInstructionBytes = 15; // architectural x86/x64 maximum

        public static List<(ulong Site, ulong Target)> FindDirectCalls(
            IMemorySource memory, bool is64Bit, IReadOnlyList<ExecutableRegion> inputRegions,
            IEnumerable<ulong> seeds, int maxEdges,
            ISet<ulong>? knownFunctionEntries = null,
            IReadOnlyList<AddressRange>? knownFunctionBodies = null)
        {
            var result = new List<(ulong Site, ulong Target)>();
            if (maxEdges <= 0 || inputRegions.Count == 0) return result;

            var regions = new List<ExecutableRegion>(inputRegions);
            regions.Sort((a, b) => a.VirtualAddress.CompareTo(b.VirtualAddress));

            var pending = new Queue<ulong>();
            var queued = new HashSet<ulong>();
            foreach (ulong seed in seeds)
                EnqueueIfMapped(seed, regions, pending, queued);

            var visited = new HashSet<ulong>();
            long scaledBudget = (long)maxEdges * 256;
            int instructionBudget = (int)Math.Min(10_000_000L, Math.Max(100_000L, scaledBudget));
            int instructions = 0;

            byte[] window = new byte[ReadWindow];
            int bitness = is64Bit ? 64 : 32;

            while (pending.Count > 0 && result.Count < maxEdges && instructions < instructionBudget)
            {
                ulong blockIp = pending.Dequeue();

                while (TryFindRegion(blockIp, regions, out var region)
                    && result.Count < maxEdges && instructions < instructionBudget)
                {
                    ulong regionOffset = blockIp - region.VirtualAddress;
                    ulong remaining = region.Length - regionOffset;
                    int want = (int)Math.Min((ulong)window.Length, remaining);
                    int read = memory.ReadMemory(region.ReadAddress + regionOffset, window.AsSpan(0, want));
                    if (read <= 0) break;

                    var reader = new ByteArrayCodeReader(window, 0, read);
                    var decoder = Decoder.Create(bitness, reader, blockIp, DecoderOptions.None);
                    bool regionHasMore = remaining > (ulong)read;
                    bool reload = false;
                    bool endBlock = false;

                    while (reader.CanReadByte && result.Count < maxEdges && instructions < instructionBudget)
                    {
                        ulong ip = decoder.IP;

                        // Preserve enough bytes for the longest x86/x64 instruction.
                        // Reload from this exact IP rather than decoding a truncated
                        // instruction at a 64 KiB window boundary.
                        ulong used = ip - blockIp;
                        if (regionHasMore && read >= MaxInstructionBytes
                            && used > (ulong)(read - MaxInstructionBytes))
                        {
                            blockIp = ip;
                            reload = true;
                            break;
                        }

                        if (!visited.Add(ip)) { endBlock = true; break; }

                        decoder.Decode(out Instruction instr);
                        instructions++;
                        if (instr.Code == Code.INVALID || instr.NextIP <= ip)
                        {
                            endBlock = true;
                            break;
                        }

                        switch (instr.FlowControl)
                        {
                            case FlowControl.Call:
                                if (IsDirectNearBranch(instr))
                                {
                                    ulong target = instr.NearBranchTarget;
                                    // A call to its own fall-through is the classic
                                    // get-IP idiom, not a subroutine invocation.
                                    if (target != instr.NextIP
                                        && TryFindRegion(target, regions, out _)
                                        && IsPotentialFunctionEntry(target,
                                            knownFunctionEntries, knownFunctionBodies))
                                    {
                                        result.Add((instr.IP, target));
                                        EnqueueIfMapped(target, regions, pending, queued);
                                    }
                                }
                                break; // calls return; keep following fall-through

                            case FlowControl.IndirectCall:
                            case FlowControl.Next:
                                break;

                            case FlowControl.ConditionalBranch:
                                EnqueueIfMapped(instr.NearBranchTarget, regions, pending, queued);
                                break; // also follow the fall-through below

                            case FlowControl.UnconditionalBranch:
                                if (IsDirectNearBranch(instr))
                                    EnqueueIfMapped(instr.NearBranchTarget, regions, pending, queued);
                                endBlock = true;
                                break;

                            default:
                                // return, indirect jump, interrupt, exception, etc.
                                endBlock = true;
                                break;
                        }

                        if (endBlock) break;
                    }

                    if (endBlock) break;
                    if (reload) continue;

                    ulong next = decoder.IP;
                    if (next <= blockIp) break;
                    blockIp = next;
                }
            }

            return result;
        }

        private static bool IsDirectNearBranch(in Instruction instr) =>
            instr.Op0Kind == OpKind.NearBranch16 ||
            instr.Op0Kind == OpKind.NearBranch32 ||
            instr.Op0Kind == OpKind.NearBranch64;

        // AMD64 unwind metadata is strong positive evidence but not a complete
        // function list: true leaf functions need no RUNTIME_FUNCTION entry.
        // Accept exact known starts and targets outside every known function body;
        // reject only a target that lands inside a known body without being its start.
        private static bool IsPotentialFunctionEntry(ulong target,
            ISet<ulong>? knownEntries, IReadOnlyList<AddressRange>? knownBodies)
        {
            if (knownEntries == null || knownBodies == null) return true;
            if (knownEntries.Contains(target)) return true;

            int lo = 0, hi = knownBodies.Count - 1;
            while (lo <= hi)
            {
                int mid = lo + ((hi - lo) >> 1);
                var range = knownBodies[mid];
                if (target < range.Start) hi = mid - 1;
                else if (range.Contains(target)) return false;
                else lo = mid + 1;
            }
            return true;
        }

        private static void EnqueueIfMapped(ulong address, IReadOnlyList<ExecutableRegion> regions,
            Queue<ulong> pending, HashSet<ulong> queued)
        {
            if (queued.Contains(address) || !TryFindRegion(address, regions, out _)) return;
            queued.Add(address);
            pending.Enqueue(address);
        }

        private static bool TryFindRegion(ulong address, IReadOnlyList<ExecutableRegion> regions,
            out ExecutableRegion region)
        {
            int lo = 0, hi = regions.Count - 1;
            while (lo <= hi)
            {
                int mid = lo + ((hi - lo) >> 1);
                var candidate = regions[mid];
                if (address < candidate.VirtualAddress) hi = mid - 1;
                else if (candidate.Contains(address)) { region = candidate; return true; }
                else lo = mid + 1;
            }
            region = default;
            return false;
        }
    }
}
