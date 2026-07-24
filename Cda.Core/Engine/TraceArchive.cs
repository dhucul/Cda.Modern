using System;
using System.IO;
using Cda.Core.Model;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Saves and reloads a captured trace — modules, discovered functions, and
    /// call records (including each record's stack snapshot, integer arguments,
    /// and decoded dereferences) — as a compact binary file, so a capture can be
    /// reopened and reviewed offline. Architecture-neutral: every address is a
    /// <see cref="ulong"/>, exactly as <see cref="CallRecord"/> stores it, so an
    /// x86 capture reloads fine in an x64 build and vice-versa.
    ///
    /// The format is deliberately simple and little-endian (matching the rest of
    /// the engine). Loading validates collection sizes, string/payload lengths,
    /// and exact reads before allocating from file-controlled values.
    /// </summary>
    public static class TraceArchive
    {
        public const string FileExtension = ".cdatrace";

        private const uint Magic = 0x54414443; // 'C''D''A''T'
        private const int Version = 2;
        private const int MaxModules = 65_536;
        private const int MaxFunctions = 10_000_000;
        private const int MaxRecords = 20_000_000;
        private const int MaxSnapshotWords = 4_096;
        private const int MaxArguments = 256;
        private const int MaxDereferences = 256;
        private const int MaxDereferenceBytes = 4_096;
        private const int MaxStringBytes = 1_048_576;

        public static void Save(string path, TraceDataset ds)
        {
            using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
            using var w = new BinaryWriter(fs, System.Text.Encoding.UTF8, leaveOpen: false);

            w.Write(Magic);
            w.Write(Version);
            w.Write(ds.TimeStart);
            w.Write(ds.TimeEnd);

            w.Write(ds.Modules.Count);
            foreach (var m in ds.Modules)
            {
                w.Write(m.Name ?? "");
                w.Write(m.BaseAddress);
                w.Write(m.Size);
                WriteOpt(w, m.Path);
                w.Write(m.PreferredBaseAddress);
            }

            w.Write(ds.Functions.Count);
            foreach (var f in ds.Functions)
            {
                w.Write(f.Address);
                w.Write(f.ModuleBase);
                w.Write(f.DisplayAddress);
                WriteOpt(w, f.Name);
                w.Write(f.CallCount);
            }

            w.Write(ds.Records.Count);
            foreach (var r in ds.Records)
            {
                w.Write(r.Time);
                w.Write(r.Source);
                w.Write(r.Destination);
                w.Write(r.StackPointer);

                var snap = r.StackSnapshot ?? Array.Empty<ulong>();
                w.Write(snap.Length);
                foreach (var s in snap) w.Write(s);

                var args = r.IntegerArgs ?? Array.Empty<ulong>();
                w.Write(args.Length);
                foreach (var a in args) w.Write(a);

                var derefs = r.Dereferences ?? Array.Empty<Dereference>();
                w.Write(derefs.Length);
                foreach (var d in derefs)
                {
                    w.Write(d.ArgumentIndex);
                    w.Write((byte)d.Kind);
                    w.Write(d.Pointer);
                    var data = d.Data ?? Array.Empty<byte>();
                    w.Write(data.Length);
                    w.Write(data);
                }
            }
        }

        public static TraceDataset Load(string path)
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var r = new BinaryReader(fs, System.Text.Encoding.UTF8, leaveOpen: false);

            if (r.ReadUInt32() != Magic) throw new InvalidDataException("Not a CDA trace file.");
            int version = r.ReadInt32();
            if (version < 1 || version > Version)
                throw new InvalidDataException($"Unsupported CDA trace version {version}.");

            var ds = new TraceDataset
            {
                TimeStart = r.ReadDouble(),
                TimeEnd = r.ReadDouble(),
            };

            int modCount = ReadCount(r, "module", MaxModules,
                minimumBytesPerItem: version >= 2 ? 26 : 18);
            for (int i = 0; i < modCount; i++)
            {
                string name = ReadString(r);
                ulong baseAddr = r.ReadUInt64();
                ulong size = r.ReadUInt64();
                string? p = ReadOpt(r);
                ulong preferredBase = version >= 2 ? r.ReadUInt64() : 0;
                ds.Modules.Add(new ModuleInfo(name, baseAddr, size, p,
                    preferredBaseAddress: preferredBase));
            }

            int fnCount = ReadCount(r, "function", MaxFunctions,
                minimumBytesPerItem: version >= 2 ? 33 : 25);
            for (int i = 0; i < fnCount; i++)
            {
                ulong addr = r.ReadUInt64();
                ulong mbase = r.ReadUInt64();
                ulong displayAddress = version >= 2 ? r.ReadUInt64() : addr;
                string? nm = ReadOpt(r);
                long cc = r.ReadInt64();
                ds.Functions.Add(new TracedFunction(addr, mbase, nm, displayAddress)
                    { CallCount = cc });
            }

            int recCount = ReadCount(r, "record", MaxRecords, minimumBytesPerItem: 44);
            if (recCount > 0) ds.Records.Capacity = recCount;
            for (int i = 0; i < recCount; i++)
            {
                var rec = new CallRecord
                {
                    Time = r.ReadDouble(),
                    Source = r.ReadUInt64(),
                    Destination = r.ReadUInt64(),
                    StackPointer = r.ReadUInt64(),
                };

                int snapN = ReadCount(r, "stack snapshot word", MaxSnapshotWords,
                    minimumBytesPerItem: sizeof(ulong));
                var snap = new ulong[snapN];
                for (int s = 0; s < snapN; s++) snap[s] = r.ReadUInt64();
                rec.StackSnapshot = snap;

                int argN = ReadCount(r, "argument", MaxArguments,
                    minimumBytesPerItem: sizeof(ulong));
                var args = new ulong[argN];
                for (int a = 0; a < argN; a++) args[a] = r.ReadUInt64();
                rec.IntegerArgs = args;

                int derefN = ReadCount(r, "dereference", MaxDereferences,
                    minimumBytesPerItem: 17);
                var derefs = new Dereference[derefN];
                for (int d = 0; d < derefN; d++)
                {
                    int ai = r.ReadInt32();
                    byte kind = r.ReadByte();
                    ulong ptr = r.ReadUInt64();
                    int dataN = ReadCount(r, "dereference payload byte", MaxDereferenceBytes,
                        minimumBytesPerItem: 1);
                    byte[] data = ReadBytesExact(r, dataN, "dereference payload");
                    derefs[d] = new Dereference
                    {
                        ArgumentIndex = ai,
                        Kind = (DereferenceKind)kind,
                        Pointer = ptr,
                        Data = data,
                    };
                }
                rec.Dereferences = derefs;
                ds.Records.Add(rec);
            }

            return ds;
        }

        private static void WriteOpt(BinaryWriter w, string? s)
        {
            w.Write(s != null);
            if (s != null) w.Write(s);
        }

        private static string? ReadOpt(BinaryReader r) => r.ReadBoolean() ? ReadString(r) : null;

        private static int ReadCount(BinaryReader r, string field, int hardMaximum,
            int minimumBytesPerItem = 0)
        {
            int value = r.ReadInt32();
            if (value < 0 || value > hardMaximum)
                throw new InvalidDataException($"Invalid {field} count: {value}.");

            if (minimumBytesPerItem > 0 && r.BaseStream.CanSeek)
            {
                long remaining = r.BaseStream.Length - r.BaseStream.Position;
                if ((long)value * minimumBytesPerItem > remaining)
                    throw new InvalidDataException(
                        $"{field} count {value} exceeds the remaining trace data.");
            }
            return value;
        }

        private static byte[] ReadBytesExact(BinaryReader r, int count, string field)
        {
            if (count < 0)
                throw new InvalidDataException($"Invalid {field} length: {count}.");
            if (r.BaseStream.CanSeek && count > r.BaseStream.Length - r.BaseStream.Position)
                throw new EndOfStreamException($"Truncated {field}.");

            byte[] data = r.ReadBytes(count);
            if (data.Length != count)
                throw new EndOfStreamException($"Truncated {field}.");
            return data;
        }

        private static string ReadString(BinaryReader r)
        {
            int byteCount;
            try { byteCount = r.Read7BitEncodedInt(); }
            catch (Exception ex) when (ex is FormatException or EndOfStreamException)
            {
                throw new InvalidDataException("Invalid trace string length.", ex);
            }
            if (byteCount < 0 || byteCount > MaxStringBytes)
                throw new InvalidDataException($"Invalid trace string length: {byteCount}.");
            return System.Text.Encoding.UTF8.GetString(
                ReadBytesExact(r, byteCount, "trace string"));
        }
    }
}
