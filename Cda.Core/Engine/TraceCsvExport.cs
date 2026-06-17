using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using Cda.Core.Model;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Exports a captured trace's call records to a spreadsheet-friendly CSV
    /// (RFC 4180), one row per call. Unlike <see cref="TraceArchive"/> — the
    /// lossless binary format meant to be reopened in CDA — this is a one-way,
    /// human/tool-readable dump for Excel, pandas, grep, etc.: addresses resolved
    /// to <c>module+0xRVA</c>, callee names where known, integer arguments, and
    /// decoded string arguments.
    ///
    /// Self-contained Core code: it builds its own <see cref="ModuleMap"/> from
    /// <see cref="TraceDataset.Modules"/> and a name lookup from
    /// <see cref="TraceDataset.Functions"/>, so it needs nothing from the UI and
    /// produces the same labels the live views show. Architecture-neutral — every
    /// address is a <see cref="ulong"/>, exactly as <see cref="CallRecord"/> stores it.
    /// </summary>
    public static class TraceCsvExport
    {
        public const string FileExtension = ".csv";

        private static readonly string[] Header =
        {
            "Index", "Time(s)", "CallerAddr", "Caller",
            "CalleeAddr", "Callee", "CalleeModule", "Args", "Strings",
        };

        public static void Export(string path, TraceDataset ds)
        {
            // UTF-8 with a BOM so Excel detects the encoding and renders decoded
            // (non-ASCII) string arguments correctly rather than as mojibake.
            using var writer = new StreamWriter(path, append: false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true))
            {
                NewLine = "\r\n", // RFC 4180 line ending, independent of platform
            };
            Write(writer, ds);
        }

        /// <summary>Writes the CSV to an arbitrary writer (testing / piping).</summary>
        public static void Write(TextWriter writer, TraceDataset ds)
        {
            var map = new ModuleMap(ds.Modules);

            // Address -> function name, for the discovered functions that have one
            // (exports / Windows-API names / PDB symbols). Synthetic sub_XXXX names
            // are skipped here so the callee column falls back to module+0xRVA.
            var names = new Dictionary<ulong, string>();
            foreach (var f in ds.Functions)
                if (!string.IsNullOrEmpty(f.Name))
                    names[f.Address] = f.Name!;

            WriteRow(writer, Header);

            var sbArgs = new StringBuilder();
            var sbStr = new StringBuilder();
            var fields = new string[Header.Length];

            for (int i = 0; i < ds.Records.Count; i++)
            {
                var r = ds.Records[i];

                sbArgs.Clear();
                var args = r.IntegerArgs;
                if (args != null)
                    for (int a = 0; a < args.Length; a++)
                    {
                        if (a > 0) sbArgs.Append(' ');
                        sbArgs.Append("0x").Append(args[a].ToString("X"));
                    }

                sbStr.Clear();
                var derefs = r.Dereferences;
                if (derefs != null)
                    foreach (var d in derefs)
                    {
                        string? s = d.AsString();
                        if (s == null) continue;
                        if (sbStr.Length > 0) sbStr.Append(" ; ");
                        sbStr.Append("arg").Append(d.ArgumentIndex).Append("=\"").Append(s).Append('"');
                    }

                fields[0] = (i + 1).ToString(CultureInfo.InvariantCulture);
                fields[1] = r.Time.ToString("0.000000", CultureInfo.InvariantCulture);
                fields[2] = "0x" + r.Source.ToString("X");
                fields[3] = map.Describe(r.Source);
                fields[4] = "0x" + r.Destination.ToString("X");
                fields[5] = names.TryGetValue(r.Destination, out var nm) ? nm : map.Describe(r.Destination);
                fields[6] = map.Resolve(r.Destination)?.Name ?? "";
                fields[7] = sbArgs.ToString();
                fields[8] = sbStr.ToString();

                WriteRow(writer, fields);
            }
        }

        private static void WriteRow(TextWriter writer, string[] fields)
        {
            for (int i = 0; i < fields.Length; i++)
            {
                if (i > 0) writer.Write(',');
                writer.Write(Escape(fields[i]));
            }
            writer.Write("\r\n");
        }

        // RFC 4180: a field is quoted only when it contains a comma, a quote, or a
        // line break; an embedded quote is doubled. AsString() already collapses
        // control chars to spaces, but a value can still hold a comma or quote.
        private static string Escape(string? field)
        {
            field ??= "";
            bool mustQuote = field.IndexOfAny(QuoteTriggers) >= 0;
            if (!mustQuote) return field;
            return "\"" + field.Replace("\"", "\"\"") + "\"";
        }

        private static readonly char[] QuoteTriggers = { ',', '"', '\r', '\n' };
    }
}
