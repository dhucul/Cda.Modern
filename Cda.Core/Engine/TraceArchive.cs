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
    /// the engine). It is meant for this tool's own files; it trusts its input
    /// beyond a magic + version check.
    /// </summary>
    public static class TraceArchive
    {
        public const string FileExtension = ".cdatrace";

        private const uint Magic = 0x54414443; // 'C''D''A''T'
        private const int Version = 1;

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
            }

            w.Write(ds.Functions.Count);
            foreach (var f in ds.Functions)
            {
                w.Write(f.Address);
                w.Write(f.ModuleBase);
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
            if (version != Version) throw new InvalidDataException($"Unsupported CDA trace version {version}.");

            var ds = new TraceDataset
            {
                TimeStart = r.ReadDouble(),
                TimeEnd = r.ReadDouble(),
            };

            int modCount = r.ReadInt32();
            for (int i = 0; i < modCount; i++)
            {
                string name = r.ReadString();
                ulong baseAddr = r.ReadUInt64();
                ulong size = r.ReadUInt64();
                string? p = ReadOpt(r);
                ds.Modules.Add(new ModuleInfo(name, baseAddr, size, p));
            }

            int fnCount = r.ReadInt32();
            for (int i = 0; i < fnCount; i++)
            {
                ulong addr = r.ReadUInt64();
                ulong mbase = r.ReadUInt64();
                string? nm = ReadOpt(r);
                long cc = r.ReadInt64();
                ds.Functions.Add(new TracedFunction(addr, mbase, nm) { CallCount = cc });
            }

            int recCount = r.ReadInt32();
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

                int snapN = r.ReadInt32();
                var snap = new ulong[snapN];
                for (int s = 0; s < snapN; s++) snap[s] = r.ReadUInt64();
                rec.StackSnapshot = snap;

                int argN = r.ReadInt32();
                var args = new ulong[argN];
                for (int a = 0; a < argN; a++) args[a] = r.ReadUInt64();
                rec.IntegerArgs = args;

                int derefN = r.ReadInt32();
                var derefs = new Dereference[derefN];
                for (int d = 0; d < derefN; d++)
                {
                    int ai = r.ReadInt32();
                    byte kind = r.ReadByte();
                    ulong ptr = r.ReadUInt64();
                    int dataN = r.ReadInt32();
                    byte[] data = r.ReadBytes(dataN);
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

        private static string? ReadOpt(BinaryReader r) => r.ReadBoolean() ? r.ReadString() : null;
    }
}
