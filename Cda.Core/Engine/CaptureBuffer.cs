using System;
using System.Buffers.Binary;

namespace Cda.Core.Engine
{
    /// <summary>
    /// In-target lock-free ring of fixed-size call records, plus a small control
    /// block, allocated in the target's address space.
    ///
    /// Each hooked thread claims a slot by atomically incrementing a sequence
    /// counter (<c>lock xadd</c> on <c>claimSeq</c>). The slot index is
    /// <c>seq &amp; (slotCount-1)</c> and the byte offset is
    /// <c>index * recordSize</c>. Because <c>slotCount</c> is a power of two the
    /// index is always in range, so the stub never writes out of bounds and needs
    /// no bounds branch — if the writer laps the reader the oldest slot is simply
    /// overwritten, but the ring is sized so that does not happen between polls.
    ///
    /// Each slot ends with a sequence/complement commit footer written after its
    /// payload. The host remembers the last sequence number it drained and copies
    /// only the contiguous committed records since then (handling wrap-around), so
    /// a claim that is still being written remains pending for the next poll. This
    /// replaces the earlier
    /// drain-then-reset buffer, which lost the tail of every batch and corrupted
    /// once the cursor ran past the end.
    ///
    /// Control block (16 bytes, little-endian):
    ///   u32 magic ('CDAR'), u32 slotCount, u32 claimSeq, u32 recordSize.
    /// </summary>
    public sealed class CaptureBuffer
    {
        public const uint Magic = 0x52414443; // 'C''D''A''R' little-endian

        public ulong ControlAddress { get; private set; }
        public ulong DataAddress { get; private set; }
        public int SlotCount { get; private set; }   // always a power of two
        public int RecordSize { get; private set; }

        /// <summary>
        /// Allocate the control block and a ring of (at least
        /// <paramref name="requestedSlots"/>, rounded up to a power of two) record
        /// slots. <paramref name="recordSize"/> is the fixed per-record size.
        /// </summary>
        // Hard ceiling on the ring's byte size, both to bound the target allocation and
        // to keep slots * recordSize well inside a 32-bit allocation size.
        private const long MaxRingBytes = 256L * 1024 * 1024;

        public static CaptureBuffer Create(ICodeMemory mem, int requestedSlots, int recordSize)
        {
            if (recordSize < CaptureStub.CommitBytes)
                throw new ArgumentOutOfRangeException(nameof(recordSize), "record size is too small for the commit footer");
            if ((long)recordSize * 256 > MaxRingBytes)
                throw new ArgumentOutOfRangeException(nameof(recordSize), "record size cannot fit the minimum ring within the byte ceiling");

            // Slot count: at least 256, a power of two, and small enough that the ring
            // (slots * recordSize bytes) stays within the ceiling. The request is clamped
            // in 64-bit BEFORE the power-of-two rounding, so neither the rounding nor the
            // byte size can overflow a 32-bit int — a huge requestedSlots or recordSize
            // would otherwise wrap to a tiny/negative allocation the stub then writes past
            // (it indexes up to slotCount-1 with no bounds check). If rounding up would
            // overshoot the ceiling, round down instead.
            long maxSlots = Math.Max(256L, MaxRingBytes / recordSize);
            int want = (int)Math.Clamp((long)requestedSlots, 256L, maxSlots);
            int slots = RoundUpPow2(want);
            if ((long)slots * recordSize > MaxRingBytes) slots = RoundDownPow2(want);
            long bytes = (long)slots * recordSize;

            var buf = new CaptureBuffer
            {
                SlotCount = slots,
                RecordSize = recordSize,
                ControlAddress = mem.Allocate(16, executable: false),
                DataAddress = mem.Allocate((int)bytes, executable: false),
            };

            Span<byte> hdr = stackalloc byte[16];
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.Slice(0), Magic);
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.Slice(4), (uint)slots);
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.Slice(8), 0);                 // claimSeq
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.Slice(12), (uint)recordSize);
            mem.Write(buf.ControlAddress, hdr);
            return buf;
        }

        /// <summary>The monotonically increasing count of slots ever claimed.</summary>
        public uint ReadClaimSeq(ICodeMemory mem)
        {
            return TryReadClaimSeq(mem, out uint claimSeq) ? claimSeq : 0;
        }

        private bool TryReadClaimSeq(ICodeMemory mem, out uint claimSeq)
        {
            claimSeq = 0;
            Span<byte> hdr = stackalloc byte[16];
            if (mem.Read(ControlAddress, hdr) < 16) return false;
            claimSeq = BinaryPrimitives.ReadUInt32LittleEndian(hdr.Slice(8));
            return true;
        }

        /// <summary>
        /// Advance <paramref name="readSeq"/> to the writer's current claim without
        /// copying or decoding the pending slots. Used to establish a precise Clear
        /// calls boundary while capture continues. Claims made after this snapshot
        /// remain pending for the next normal drain.
        /// </summary>
        public bool DiscardSince(ICodeMemory mem, ref uint readSeq, out int recordsLost)
        {
            recordsLost = 0;
            if (!TryReadClaimSeq(mem, out uint claim)) return false;

            uint delta = claim - readSeq; // unsigned subtraction: wrap-safe
            uint slots = (uint)SlotCount;
            if (delta > slots)
                recordsLost = (int)Math.Min(delta - slots, (uint)int.MaxValue);
            readSeq = claim;
            return true;
        }

        /// <summary>
        /// Copy every contiguous committed record since <paramref name="readSeq"/> into a
        /// contiguous, in-order byte buffer, then advance <paramref name="readSeq"/>
        /// through the latest safely published claim. Records wrap around the end of
        /// the ring, so each snapshot may issue two reads. If the writer got more than a full ring ahead (lapping),
        /// only the most recent <see cref="SlotCount"/> records survive and the rest
        /// are reported in <paramref name="recordsLost"/>.
        /// </summary>
        public byte[] DrainSince(ICodeMemory mem, ref uint readSeq, out int recordsLost)
        {
            recordsLost = 0;

            // Tell a real zero counter from a failed read (e.g. target exit).
            if (!TryReadClaimSeq(mem, out uint claim)) return Array.Empty<byte>();

            uint delta = claim - readSeq;          // unsigned subtraction: wrap-safe
            if (delta == 0) return Array.Empty<byte>();

            uint slots = (uint)SlotCount;
            uint start = readSeq;
            int pendingLost = 0;
            if (delta > slots)                     // writer lapped the reader
            {
                pendingLost = (int)Math.Min(delta - slots, (uint)int.MaxValue);
                start = claim - slots;             // keep only the freshest full ring
                delta = slots;
            }

            int rec = RecordSize;
            byte[] snapshot = new byte[(int)delta * rec];
            ulong[] firstCommits = new ulong[delta];
            int commitOff = rec - CaptureStub.CommitBytes;

            // Read twice. A committed marker in both snapshots proves that the
            // writer completed this sequence before the first copy and did not
            // begin reusing its slot before the second copy completed.
            if (!TryReadRange(mem, start, delta, snapshot))
                return Array.Empty<byte>();
            for (uint i = 0; i < delta; i++)
            {
                int off = (int)i * rec + commitOff;
                firstCommits[i] = BinaryPrimitives.ReadUInt64LittleEndian(snapshot.AsSpan(off));
            }
            if (!TryReadRange(mem, start, delta, snapshot))
                return Array.Empty<byte>();

            uint committed = 0;
            for (; committed < delta; committed++)
            {
                uint expected = start + committed;
                int off = (int)committed * rec + commitOff;
                ulong first = firstCommits[committed];
                uint seq1 = (uint)first;
                uint inv1 = (uint)(first >> 32);
                uint seq2 = BinaryPrimitives.ReadUInt32LittleEndian(snapshot.AsSpan(off));
                uint inv2 = BinaryPrimitives.ReadUInt32LittleEndian(snapshot.AsSpan(off + 4));
                if (seq1 != expected || inv1 != ~expected ||
                    seq2 != expected || inv2 != ~expected)
                    break;
            }

            // Anything before 'start' was already overwritten and is irrecoverable.
            // An uncommitted slot at/after start remains pending for the next poll.
            readSeq = start + committed;
            recordsLost = pendingLost;
            if (committed == 0) return Array.Empty<byte>();
            if (committed < delta)
                Array.Resize(ref snapshot, (int)committed * rec);
            return snapshot;
        }

        private bool TryReadRange(ICodeMemory mem, uint start, uint count, Span<byte> destination)
        {
            int rec = RecordSize;
            uint slots = (uint)SlotCount;
            uint mask = slots - 1;
            uint startIndex = start & mask;
            uint firstCount = Math.Min(count, slots - startIndex);
            int firstBytes = (int)firstCount * rec;
            if (mem.Read(DataAddress + (ulong)(startIndex * (uint)rec),
                    destination.Slice(0, firstBytes)) != firstBytes)
                return false;

            uint second = count - firstCount;
            if (second == 0) return true;
            int secondBytes = (int)second * rec;
            return mem.Read(DataAddress, destination.Slice(firstBytes, secondBytes)) == secondBytes;
        }

        private static int RoundUpPow2(int v)
        {
            if (v < 1) return 1;
            v--; v |= v >> 1; v |= v >> 2; v |= v >> 4; v |= v >> 8; v |= v >> 16; v++;
            return v;
        }

        // Largest power of two <= v (v >= 1).
        private static int RoundDownPow2(int v)
        {
            if (v < 1) return 1;
            v |= v >> 1; v |= v >> 2; v |= v >> 4; v |= v >> 8; v |= v >> 16;
            return v - (v >> 1);
        }
    }
}
