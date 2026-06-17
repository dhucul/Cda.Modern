using System;
using System.Collections.Generic;
using Cda.Core.Model;
using Cda.Core.Pe;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Discovers the functions a target's own modules <b>export</b>, resolved to
    /// their live entry-point addresses, so a <see cref="CaptureSession"/> can hook
    /// them.
    ///
    /// This is the mirror of <see cref="ApiImportScanner"/>: where that finds the
    /// calls a program makes OUT to the OS (its imports), this finds the program's
    /// own public surface — the functions its EXE and its own DLLs expose for other
    /// code to call IN to. For each of the app's modules (everything not under the
    /// Windows directory) it:
    ///   1. reads the mapped image and parses the export directory (<see cref="PeImage"/>);
    ///   2. keeps the exports that point at real code in this module — dropping
    ///      <b>forwarders</b> (an export whose "RVA" is really a "OtherDll.Func"
    ///      string; its code lives in another module, reached via that module's own
    ///      exports) and any zero-RVA holes in the export table;
    ///   3. resolves each surviving export to its live VA as
    ///      <c>module base + export RVA</c> — exports are relative to the image base,
    ///      so this is exact regardless of ASLR.
    ///
    /// Hooking those entries captures every call INTO the module's exported
    /// functions. Unlike discovery-by-call-site (<see cref="CallSiteScanner"/>),
    /// exports are authoritative function entries, so the set needs no heuristics and
    /// is always safe to splice.
    /// </summary>
    public static class ExportScanner
    {
        // Don't pull a giant module into a managed buffer just to read its export
        // table; app modules are small. A module bigger than this is skipped (and
        // reported) rather than read in full. Matches ApiImportScanner's cap.
        private const long MaxModuleImageBytes = 96L * 1024 * 1024;

        // Safety ceiling on distinct entries collected (the UI caps the hooked subset
        // separately). A DLL can export thousands; this bounds the discovery itself.
        private const int MaxEntries = 4096;

        public sealed class Result
        {
            /// <summary>One <see cref="TracedFunction"/> per distinct resolved export entry.</summary>
            public List<TracedFunction> Functions = new();

            /// <summary>The app modules those exports live in (for the views/graph).</summary>
            public List<ModuleInfo> Modules = new();

            /// <summary>App modules whose exports were scanned (had at least one export).</summary>
            public List<ModuleInfo> ScannedModules = new();

            /// <summary>How many exports were dropped because they forward to another DLL.</summary>
            public int SkippedForwarders;

            /// <summary>App modules skipped for being larger than the read cap.</summary>
            public int SkippedLargeModules;
        }

        /// <summary>
        /// Walk the export tables of <paramref name="map"/>'s app modules and return
        /// their exported functions, resolved in <paramref name="process"/>.
        /// Read-only against the target.
        /// </summary>
        public static Result Discover(TargetProcess process, ModuleMap map)
        {
            var result = new Result();

            string winDir = "";
            try { winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows); }
            catch { /* leave empty: then nothing is classified system and we no-op safely */ }

            // Distinct resolved entry, so the same address exported under two names
            // (a common aliasing) is hooked once.
            var seen = new HashSet<ulong>();
            var nodeModules = new Dictionary<ulong, ModuleInfo>();

            foreach (var module in map.Modules)
            {
                // Only the app's OWN modules — hooking the OS's thousands of exports
                // is the Windows-API path's job (ApiImportScanner), not this one.
                if (IsSystemModule(module, winDir)) continue;
                if (module.Size == 0) continue;
                if (module.Size > (ulong)MaxModuleImageBytes) { result.SkippedLargeModules++; continue; }

                byte[]? image = ReadImage(process, module);
                if (image == null) continue;

                PeImage pe;
                try { pe = PeImage.FromMappedImage(image, module.BaseAddress); }
                catch { continue; } // not a readable PE image right now — skip

                List<PeExport> exports;
                try { exports = pe.ReadExports(); }
                catch { continue; }

                bool scannedAny = false;
                foreach (var exp in exports)
                {
                    if (exp.IsForwarder) { result.SkippedForwarders++; continue; }
                    if (exp.Rva == 0) continue; // hole in the export-address table

                    ulong target = module.BaseAddress + exp.Rva;
                    if (!seen.Add(target)) continue;

                    string declared = TrimDllExtension(module.Name);
                    string func = exp.Name ?? ("#" + exp.Ordinal);
                    string label = declared.Length > 0 ? declared + "!" + func : func;

                    result.Functions.Add(new TracedFunction(target, module.BaseAddress, label));
                    nodeModules[module.BaseAddress] = module;
                    scannedAny = true;

                    if (result.Functions.Count >= MaxEntries) break;
                }

                if (scannedAny) result.ScannedModules.Add(module);
                if (result.Functions.Count >= MaxEntries) break;
            }

            foreach (var m in nodeModules.Values) result.Modules.Add(m);

            // Tidy, stable ordering: group by module, then function name.
            result.Functions.Sort((a, b) =>
                string.Compare(a.DisplayName, b.DisplayName, StringComparison.OrdinalIgnoreCase));

            return result;
        }

        private static bool IsSystemModule(ModuleInfo m, string winDir)
        {
            if (winDir.Length == 0 || string.IsNullOrEmpty(m.Path)) return false;
            return m.Path!.StartsWith(winDir, StringComparison.OrdinalIgnoreCase);
        }

        // Read a module's mapped image into a managed buffer, chunked so an
        // unreadable page (guard page, decommitted region) leaves a zero gap instead
        // of failing the whole read. The export directory, name table, and address
        // table all live within the image, addressed by RVA == offset. Mirrors
        // ApiImportScanner.ReadImage.
        private static byte[]? ReadImage(TargetProcess process, ModuleInfo module)
        {
            int size = (int)Math.Min(module.Size, (ulong)int.MaxValue);
            if (size <= 0) return null;

            byte[] image;
            try { image = new byte[size]; }
            catch (OutOfMemoryException) { return null; }

            const int chunk = 0x10000;
            bool any = false;
            for (int off = 0; off < size; off += chunk)
            {
                int len = Math.Min(chunk, size - off);
                int read = process.ReadMemory(module.BaseAddress + (ulong)off, image.AsSpan(off, len));
                if (read > 0) any = true;
            }
            return any ? image : null;
        }

        private static string TrimDllExtension(string name)
        {
            if (string.IsNullOrEmpty(name)) return "";
            if (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                return name.Substring(0, name.Length - 4);
            return name;
        }
    }
}
