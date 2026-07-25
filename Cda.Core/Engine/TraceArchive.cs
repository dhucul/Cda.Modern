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
        private const int Version = 3;
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
            if (path == null) throw new ArgumentNullException(nameof(path));
            if (ds == null) throw new ArgumentNullException(nameof(ds));
            ValidateForSave(ds);

            string fullPath = Path.GetFullPath(path);
            string directory = Path.GetDirectoryName(fullPath)
                ?? throw new ArgumentException("The trace path has no parent directory.", nameof(path));
            string tempPath = Path.Combine(directory,
                "." + Path.GetFileName(fullPath) + "." + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                SaveCore(tempPath, ds);
                if (File.Exists(fullPath)) File.Replace(tempPath, fullPath, null);
                else File.Move(tempPath, fullPath);
            }
            finally
            {
                if (File.Exists(tempPath))
                {
                    try { File.Delete(tempPath); } catch { /* preserve the original save error */ }
                }
            }
        }

        private static void SaveCore(string path, TraceDataset ds)
        {
            using var fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            using var w = new BinaryWriter(fs, System.Text.Encoding.UTF8, leaveOpen: true);
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
                foreach (var d in derefs) WriteDereference(w, d);

                // Version 3: preserve return-pairing state so an offline trace shows
                // the same completed return values as the live Calls view.
                w.Write(r.CorrelationId);
                w.Write(r.IsReturn);
                w.Write(r.HasReturned);
                w.Write(r.ReturnValue);
                w.Write(r.ReturnDereference != null);
                if (r.ReturnDereference != null) WriteDereference(w, r.ReturnDereference);
            }
            w.Flush();
            fs.Flush(flushToDisk: true);
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
            ValidateTimeRange(ds.TimeStart, ds.TimeEnd);

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

            int recCount = ReadCount(r, "record", MaxRecords,
                minimumBytesPerItem: version >= 3 ? 59 : 44);
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
                if (!double.IsFinite(rec.Time))
                    throw new InvalidDataException("A call record has a non-finite timestamp.");

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
                    derefs[d] = ReadDereference(r);
                rec.Dereferences = derefs;

                if (version >= 3)
                {
                    rec.CorrelationId = r.ReadUInt32();
                    rec.IsReturn = r.ReadBoolean();
                    rec.HasReturned = r.ReadBoolean();
                    rec.ReturnValue = r.ReadUInt64();
                    if (r.ReadBoolean()) rec.ReturnDereference = ReadDereference(r);
                }
                ds.Records.Add(rec);
            }

            return ds;
        }

        private static void WriteOpt(BinaryWriter w, string? s)
        {
            w.Write(s != null);
            if (s != null) w.Write(s);
        }

        private static void WriteDereference(BinaryWriter w, Dereference d)
        {
            w.Write(d.ArgumentIndex);
            w.Write((byte)d.Kind);
            w.Write(d.Pointer);
            var data = d.Data ?? Array.Empty<byte>();
            w.Write(data.Length);
            w.Write(data);
        }

        private static Dereference ReadDereference(BinaryReader r)
        {
            int ai = r.ReadInt32();
            byte kind = r.ReadByte();
            ulong ptr = r.ReadUInt64();
            int dataN = ReadCount(r, "dereference payload byte", MaxDereferenceBytes,
                minimumBytesPerItem: 1);
            byte[] data = ReadBytesExact(r, dataN, "dereference payload");
            return new Dereference
            {
                ArgumentIndex = ai,
                Kind = (DereferenceKind)kind,
                Pointer = ptr,
                Data = data,
            };
        }

        private static void ValidateForSave(TraceDataset ds)
        {
            CheckCount(ds.Modules.Count, MaxModules, "module");
            CheckCount(ds.Functions.Count, MaxFunctions, "function");
            CheckCount(ds.Records.Count, MaxRecords, "record");
            ValidateTimeRange(ds.TimeStart, ds.TimeEnd);

            foreach (var m in ds.Modules)
            {
                if (m == null) throw new InvalidDataException("A module entry is null.");
                CheckString(m.Name, "module name");
                CheckString(m.Path, "module path");
            }
            foreach (var f in ds.Functions)
            {
                if (f == null) throw new InvalidDataException("A function entry is null.");
                CheckString(f.Name, "function name");
            }
            foreach (var record in ds.Records)
            {
                if (record == null) throw new InvalidDataException("A call record is null.");
                if (!double.IsFinite(record.Time))
                    throw new InvalidDataException("A call record has a non-finite timestamp.");
                CheckCount(record.StackSnapshot?.Length ?? 0, MaxSnapshotWords, "stack snapshot word");
                CheckCount(record.IntegerArgs?.Length ?? 0, MaxArguments, "argument");
                CheckCount(record.Dereferences?.Length ?? 0, MaxDereferences, "dereference");
                foreach (var d in record.Dereferences ?? Array.Empty<Dereference>())
                    ValidateDereference(d);
                if (record.ReturnDereference != null) ValidateDereference(record.ReturnDereference);
            }
        }

        private static void ValidateDereference(Dereference d)
        {
            if (d == null) throw new InvalidDataException("A dereference entry is null.");
            CheckCount(d.Data?.Length ?? 0, MaxDereferenceBytes, "dereference payload byte");
        }

        private static void CheckString(string? value, string field)
        {
            if (value == null) return;
            int bytes = System.Text.Encoding.UTF8.GetByteCount(value);
            if (bytes > MaxStringBytes)
                throw new InvalidDataException($"{field} exceeds {MaxStringBytes} UTF-8 bytes.");
        }

        private static void CheckCount(int value, int hardMaximum, string field)
        {
            if (value < 0 || value > hardMaximum)
                throw new InvalidDataException($"Invalid {field} count: {value}.");
        }

        private static void ValidateTimeRange(double start, double end)
        {
            if (!double.IsFinite(start) || !double.IsFinite(end) || end < start)
                throw new InvalidDataException("The trace has an invalid time range.");
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
