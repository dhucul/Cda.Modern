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
    ///   u32 argCount
    ///   u64[argCount]     captured integer args (zero-extended on x86)
    ///   u32 stackSlots
    ///   u64[stackSlots]   raw stack words from the entry SP upward (zero-extended)
    ///   u32 derefCount
    ///   derefCount × {
    ///       u32 argumentIndex
    ///       u32 kind          (DereferenceKind)
    ///       u32 dataLen
    ///       u8[dataLen] data
    ///   }
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
            ReadOnlySpan<byte> buffer, ulong qpcBase, double qpcFrequency)
        {
            var result = new List<CallRecord>();
            double freq = qpcFrequency > 0 ? qpcFrequency : 1.0;
            int pos = 0;

            while (pos + FixedHeader <= buffer.Length)
            {
                int start = pos;
                ulong ts = BinaryPrimitives.ReadUInt64LittleEndian(buffer.Slice(pos)); pos += 8;
                ulong src = BinaryPrimitives.ReadUInt64LittleEndian(buffer.Slice(pos)); pos += 8;
                ulong dst = BinaryPrimitives.ReadUInt64LittleEndian(buffer.Slice(pos)); pos += 8;
                ulong sp = BinaryPrimitives.ReadUInt64LittleEndian(buffer.Slice(pos)); pos += 8;
                uint argc = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(pos)); pos += 4;

                if (argc > 256) break; // corrupt / wrapped; stop
                if (pos + (int)argc * 8 + 4 > buffer.Length) { pos = start; break; }

                var args = new ulong[argc];
                for (int i = 0; i < argc; i++)
                {
                    args[i] = BinaryPrimitives.ReadUInt64LittleEndian(buffer.Slice(pos));
                    pos += 8;
                }

                // Stack snapshot (entry SP upward), for host-side caller walking.
                if (pos + 4 > buffer.Length) { pos = start; break; }
                uint stackSlots = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(pos)); pos += 4;
                if (stackSlots > 4096) break;
                if (pos + (int)stackSlots * 8 + 4 > buffer.Length) { pos = start; break; }
                var snapshot = new ulong[stackSlots];
                for (int i = 0; i < stackSlots; i++)
                {
                    snapshot[i] = BinaryPrimitives.ReadUInt64LittleEndian(buffer.Slice(pos));
                    pos += 8;
                }

                uint derefc = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(pos)); pos += 4;
                if (derefc > 256) break;

                var derefs = new List<Dereference>((int)derefc);
                bool truncated = false;
                for (int d = 0; d < derefc; d++)
                {
                    if (pos + 12 > buffer.Length) { truncated = true; break; }
                    uint argIndex = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(pos)); pos += 4;
                    uint kind = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(pos)); pos += 4;
                    uint len = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(pos)); pos += 4;
                    if (len > 4096 || pos + (int)len > buffer.Length) { truncated = true; break; }

                    var data = buffer.Slice(pos, (int)len).ToArray(); pos += (int)len;
                    derefs.Add(new Dereference
                    {
                        ArgumentIndex = (int)argIndex,
                        Kind = (DereferenceKind)(byte)kind,
                        Data = data,
                    });
                }
                if (truncated) { pos = start; break; }

                double time = (double)(ts - qpcBase) / freq;
                result.Add(new CallRecord
                {
                    Time = time,
                    Source = src,
                    Destination = dst,
                    StackPointer = sp,
                    StackSnapshot = snapshot,
                    IntegerArgs = args,
                    Dereferences = derefs.ToArray(),
                });
            }

            return result;
        }
    }
}
