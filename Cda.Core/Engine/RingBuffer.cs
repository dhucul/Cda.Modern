using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Cda.Core.Model;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Host-side decoder for the in-target call-record ring buffer — the modern,
    /// 64-bit replacement for the legacy circular-buffer reader and
    /// <c>oSingleData</c> byte parsing. It defines the wire format the (future)
    /// capture stub writes, and turns a snapshot of that buffer into
    /// <see cref="CallRecord"/>s.
    ///
    /// Record layout (little-endian, all offsets in bytes):
    ///   u64 timestamp     QueryPerformanceCounter ticks at the call
    ///   u64 source        call site
    ///   u64 destination   callee entry
    ///   u64 stackPointer  ESP/RSP at entry
    ///   u32 argCount      high bit (<see cref="CaptureStub.KindReturn"/>) marks a return record
    ///   u32 correlationId claim sequence of the call — pairs a return with its call
    ///   u64[argCount]     captured integer args (zero-extended on x86); args[0] is the
    ///                     return value in a return record
    ///   u32 stackSlots
    ///   u64[stackSlots]   raw stack words from the entry SP upward (zero-extended)
    ///   u32 derefCount
    ///   derefCount × {
    ///       u32 argumentIndex
    ///       u32 kind          (DereferenceKind)
    ///       u32 dataLen
    ///       u8[dataLen] data
    ///   }
    ///   u32 commitSequence
    ///   u32 commitSequenceInverse
    /// The commit footer is publication metadata and is not part of the decoded
    /// payload.
    /// </summary>
    public static class RingBufferReader
    {
        private const int FixedHeader = 8 + 8 + 8 + 8 + 4; // through argCount

        /// <summary>
        /// Decode all complete records in <paramref name="buffer"/>. Timestamps
        /// are converted to seconds relative to <paramref name="qpcBase"/> using
        /// <paramref name="qpcFrequency"/> (ticks per second).
        /// </summary>
        public static List<CallRecord> Decode(
            ReadOnlySpan<byte> buffer, int recordSize, ulong qpcBase, double qpcFrequency)
        {
            var result = new List<CallRecord>();
            double freq = qpcFrequency > 0 ? qpcFrequency : 1.0;
            if (recordSize < CaptureStub.CommitBytes)
                return result;
            int payloadSize = recordSize - CaptureStub.CommitBytes;
            if (payloadSize < FixedHeader + 8)
                return result;

            // The target ring is fixed-stride. Decode exactly one logical record
            // from each committed slot so corrupt metadata in one slot can never
            // shift the starting point of every record that follows it.
            for (int slotStart = 0; slotStart <= buffer.Length - recordSize; slotStart += recordSize)
            {
                ReadOnlySpan<byte> slot = buffer.Slice(slotStart, payloadSize);
                int pos = 0;
                ulong ts = BinaryPrimitives.ReadUInt64LittleEndian(slot.Slice(pos)); pos += 8;
                ulong src = BinaryPrimitives.ReadUInt64LittleEndian(slot.Slice(pos)); pos += 8;
                ulong dst = BinaryPrimitives.ReadUInt64LittleEndian(slot.Slice(pos)); pos += 8;
                ulong sp = BinaryPrimitives.ReadUInt64LittleEndian(slot.Slice(pos)); pos += 8;
                uint argcRaw = BinaryPrimitives.ReadUInt32LittleEndian(slot.Slice(pos)); pos += 4;
                bool isReturn = (argcRaw & CaptureStub.KindReturn) != 0;
                uint argc = argcRaw & ~CaptureStub.KindReturn;

                if (argc > 256 || pos + 4 > slot.Length) continue;
                uint corrId = BinaryPrimitives.ReadUInt32LittleEndian(slot.Slice(pos)); pos += 4;
                if (pos + (int)argc * 8 + 4 > slot.Length) continue;

                var args = new ulong[argc];
                for (int i = 0; i < argc; i++)
                {
                    args[i] = BinaryPrimitives.ReadUInt64LittleEndian(slot.Slice(pos));
                    pos += 8;
                }

                // Stack snapshot (entry SP upward), for host-side caller walking.
                if (pos + 4 > slot.Length) continue;
                uint stackSlots = BinaryPrimitives.ReadUInt32LittleEndian(slot.Slice(pos)); pos += 4;
                int snapshotStart = pos;
                if (stackSlots > CaptureStub.StackSlots ||
                    snapshotStart + CaptureStub.StackSlots * 8 + 4 > slot.Length) continue;
                var snapshot = new ulong[stackSlots];
                for (int i = 0; i < stackSlots; i++)
                {
                    snapshot[i] = BinaryPrimitives.ReadUInt64LittleEndian(
                        slot.Slice(snapshotStart + i * 8));
                }
                pos = snapshotStart + CaptureStub.StackSlots * 8;

                uint derefc = BinaryPrimitives.ReadUInt32LittleEndian(slot.Slice(pos)); pos += 4;
                if (derefc > 256) continue;

                var derefs = new List<Dereference>((int)derefc);
                bool truncated = false;
                for (int d = 0; d < derefc; d++)
                {
                    if (pos + 12 > slot.Length) { truncated = true; break; }
                    uint argIndex = BinaryPrimitives.ReadUInt32LittleEndian(slot.Slice(pos)); pos += 4;
                    uint kind = BinaryPrimitives.ReadUInt32LittleEndian(slot.Slice(pos)); pos += 4;
                    uint len = BinaryPrimitives.ReadUInt32LittleEndian(slot.Slice(pos)); pos += 4;
                    if (len > 4096 || pos + (int)len > slot.Length) { truncated = true; break; }

                    var data = slot.Slice(pos, (int)len).ToArray(); pos += (int)len;
                    derefs.Add(new Dereference
                    {
                        ArgumentIndex = (int)argIndex,
                        Kind = (DereferenceKind)(byte)kind,
                        Data = data,
                    });
                }
                // A target record occupies the complete payload region. Reject a
                // slot whose counts leave trailing bytes or overrun the boundary.
                if (truncated || pos != slot.Length) continue;

                // Clamp: cross-core rdtsc skew (or the base not being the earliest record)
                // can make ts < qpcBase; an unsigned subtraction would then wrap to a huge
                // time and misplace the row on the timeline.
                double time = ts >= qpcBase ? (double)(ts - qpcBase) / freq : 0;
                result.Add(new CallRecord
                {
                    Time = time,
                    Source = src,
                    Destination = dst,
                    StackPointer = sp,
                    StackSnapshot = snapshot,
                    IntegerArgs = args,
                    Dereferences = derefs.ToArray(),
                    CorrelationId = corrId,
                    IsReturn = isReturn,
                });
            }

            return result;
        }
    }
}
