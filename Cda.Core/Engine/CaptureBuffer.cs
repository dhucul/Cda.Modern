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
    /// The host remembers the last sequence number it drained and copies only the
    /// records claimed since then (in one or two reads, handling wrap-around), so
    /// nothing is dropped at poll boundaries. This replaces the earlier
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
            if (recordSize <= 0) throw new ArgumentOutOfRangeException(nameof(recordSize), "record size must be positive");

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
            Span<byte> hdr = stackalloc byte[16];
            mem.Read(ControlAddress, hdr);
            return BinaryPrimitives.ReadUInt32LittleEndian(hdr.Slice(8));
        }

        /// <summary>
        /// Copy every record claimed since <paramref name="readSeq"/> into a
        /// contiguous, in-order byte buffer, then advance <paramref name="readSeq"/>
        /// to the latest claim. Records wrap around the end of the ring, so this may
        /// issue two reads. If the writer got more than a full ring ahead (lapping),
        /// only the most recent <see cref="SlotCount"/> records survive and the rest
        /// are reported in <paramref name="recordsLost"/>.
        /// </summary>
        public byte[] DrainSince(ICodeMemory mem, ref uint readSeq, out int recordsLost)
        {
            recordsLost = 0;

            // Read the control block directly so we can tell a real zero counter
            // from a failed read (e.g. the target has exited): if we can't read the
            // full 16-byte control block, there's nothing to drain.
            Span<byte> hdr = stackalloc byte[16];
            if (mem.Read(ControlAddress, hdr) < 16) return Array.Empty<byte>();
            uint claim = BinaryPrimitives.ReadUInt32LittleEndian(hdr.Slice(8));

            uint delta = claim - readSeq;          // unsigned subtraction: wrap-safe
            if (delta == 0) return Array.Empty<byte>();

            uint slots = (uint)SlotCount;
            uint start = readSeq;
            if (delta > slots)                     // writer lapped the reader
            {
                recordsLost = (int)(delta - slots);
                start = claim - slots;             // keep only the freshest full ring
                delta = slots;
            }

            int rec = RecordSize;
            uint mask = slots - 1;
            byte[] outBuf = new byte[(int)delta * rec];

            uint startIndex = start & mask;
            uint firstCount = Math.Min(delta, slots - startIndex);
            mem.Read(DataAddress + (ulong)(startIndex * (uint)rec),
                     outBuf.AsSpan(0, (int)firstCount * rec));

            uint second = delta - firstCount;      // wrapped tail, if any
            if (second > 0)
                mem.Read(DataAddress, outBuf.AsSpan((int)firstCount * rec, (int)second * rec));

            readSeq = claim;
            return outBuf;
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
