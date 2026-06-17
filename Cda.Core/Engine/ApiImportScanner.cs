using System;
using System.Collections.Generic;
using Cda.Core.Model;
using Cda.Core.Pe;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Discovers the Windows API functions a target imports, resolved to their
    /// live entry-point addresses, so a <see cref="CaptureSession"/> can hook
    /// them.
    ///
    /// Where <see cref="CallSiteScanner"/> finds a program's OWN functions
    /// (direct-call targets inside a module), this finds the program's calls OUT
    /// to the operating system. For each of the app's modules (the EXE and its
    /// own DLLs — everything not under the Windows directory) it:
    ///   1. reads the mapped image and parses the import table (<see cref="PeImage"/>);
    ///   2. reads each bound IAT slot from the live target — that holds the
    ///      address the loader resolved the import to, with forwarders already
    ///      followed (so KERNEL32!CreateFileW lands at its real KERNELBASE entry);
    ///   3. keeps only entries that resolve INTO a Windows system module.
    ///
    /// Hooking those entries captures every call the process makes to them. The
    /// import name (e.g. "kernel32!CreateFileW") is used as the label even when
    /// the export is forwarded, because that is what the programmer called.
    /// </summary>
    public static class ApiImportScanner
    {
        // Re-entrant / extremely hot primitives that are unsafe or pure noise to
        // hook process-wide: they fire constantly from every thread, can lap the
        // ring (records lost) and add real overhead to the target. Excluded by
        // default — the same lesson the startup trace encodes when it skips its
        // hottest discovered functions. A user who wants one of these can click it
        // in the list to focus the trace on just it.
        private static readonly HashSet<string> HotPrimitives = new(StringComparer.OrdinalIgnoreCase)
        {
            "EnterCriticalSection", "LeaveCriticalSection", "TryEnterCriticalSection",
            "RtlEnterCriticalSection", "RtlLeaveCriticalSection", "RtlTryEnterCriticalSection",
            "HeapAlloc", "HeapFree", "HeapReAlloc",
            "RtlAllocateHeap", "RtlFreeHeap", "RtlReAllocateHeap",
            "GetLastError", "SetLastError", "RtlGetLastWin32Error", "RtlSetLastWin32Error",
        };

        // Don't pull an entire giant module into a managed buffer just to read its
        // import table; app modules that import the OS surface are small. A module
        // bigger than this is skipped (and reported) rather than read in full.
        private const long MaxModuleImageBytes = 96L * 1024 * 1024;

        // A safety ceiling on distinct entries collected (the UI caps the hooked
        // subset separately). Normal apps are far below this.
        private const int MaxEntries = 4096;

        public sealed class Result
        {
            /// <summary>One <see cref="TracedFunction"/> per distinct resolved API entry.</summary>
            public List<TracedFunction> Functions = new();

            /// <summary>The Windows system modules those entries live in (for the views/graph).</summary>
            public List<ModuleInfo> ApiModules = new();

            /// <summary>App modules whose imports were scanned.</summary>
            public List<ModuleInfo> ScannedModules = new();

            /// <summary>How many imports were dropped because they are hot primitives.</summary>
            public int ExcludedHot;

            /// <summary>App modules skipped for being larger than the read cap.</summary>
            public int SkippedLargeModules;
        }

        /// <summary>One bound import slot: where its pointer lives, and what it resolves to.</summary>
        public sealed class ImportSlot
        {
            public ulong SlotVa;      // VA of the IAT slot (overwrite here to hook)
            public ulong Target;      // resolved real function the slot currently points at
            public ulong OwnerBase;   // base of the system module Target lives in
            public string Label = ""; // e.g. "kernel32!CreateFileW"
        }

        /// <summary>Per-slot discovery result for IAT hooking (see <see cref="DiscoverImportSlots"/>).</summary>
        public sealed class SlotResult
        {
            public List<ImportSlot> Slots = new();
            public List<ModuleInfo> ApiModules = new();
            public List<ModuleInfo> ScannedModules = new();
            public int ExcludedHot;
            public int SkippedLargeModules;
        }

        /// <summary>
        /// Walk the import tables of <paramref name="map"/>'s app modules and
        /// return their Windows-API entry points, resolved in <paramref name="process"/>.
        /// Read-only against the target.
        /// </summary>
        public static Result Discover(TargetProcess process, ModuleMap map)
        {
            var result = new Result();

            string winDir = "";
            try { winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows); }
            catch { /* leave empty: then nothing is classified system and we no-op safely */ }

            int ptr = process.Is64Bit ? 8 : 4;
            byte[] slot = new byte[ptr];

            // Distinct resolved entry -> the function we recorded for it.
            var seen = new HashSet<ulong>();
            // Distinct owning system module base -> ModuleInfo, so the views label them.
            var apiModules = new Dictionary<ulong, ModuleInfo>();

            foreach (var module in map.Modules)
            {
                // Only the app's OWN modules import the OS surface we care about;
                // a system module's imports are the OS calling itself.
                if (IsSystemModule(module, winDir)) continue;
                if (module.Size == 0) continue;
                if (module.Size > (ulong)MaxModuleImageBytes) { result.SkippedLargeModules++; continue; }

                byte[]? image = ReadImage(process, module);
                if (image == null) continue;

                PeImage pe;
                try { pe = PeImage.FromMappedImage(image, module.BaseAddress); }
                catch { continue; } // not a readable PE image right now — skip

                List<PeImport> imports;
                try { imports = pe.ReadImports(); }
                catch { continue; }

                if (imports.Count > 0) result.ScannedModules.Add(module);

                foreach (var imp in imports)
                {
                    string func = imp.ByOrdinal ? "#" + imp.Ordinal : imp.Name!;
                    if (HotPrimitives.Contains(func)) { result.ExcludedHot++; continue; }

                    // The loader-resolved entry lives in the bound IAT slot.
                    ulong iatVa = module.BaseAddress + imp.IatRva;
                    int n = process.ReadMemory(iatVa, slot);
                    if (n < ptr) continue;
                    ulong target = ptr == 8 ? BitConverter.ToUInt64(slot, 0) : BitConverter.ToUInt32(slot, 0);
                    if (target == 0) continue;

                    // Keep only entries that land in a Windows system module.
                    var owner = map.Resolve(target);
                    if (owner == null || !IsSystemModule(owner, winDir)) continue;

                    if (!seen.Add(target)) continue; // same entry imported elsewhere

                    string declared = TrimDllExtension(imp.ModuleName);
                    string label = declared.Length > 0 ? declared + "!" + func : func;
                    result.Functions.Add(new TracedFunction(target, owner.BaseAddress, label));
                    apiModules[owner.BaseAddress] = owner;

                    if (result.Functions.Count >= MaxEntries) break;
                }

                if (result.Functions.Count >= MaxEntries) break;
            }

            foreach (var m in apiModules.Values) result.ApiModules.Add(m);

            // Tidy, stable ordering: group by DLL, then function name.
            result.Functions.Sort((a, b) =>
                string.Compare(a.DisplayName, b.DisplayName, StringComparison.OrdinalIgnoreCase));

            return result;
        }

        /// <summary>
        /// Like <see cref="Discover"/>, but returns one entry per bound IAT *slot*
        /// (the data pointer the loader filled with the import's resolved address),
        /// for IAT hooking: overwriting the slot reroutes the call without touching
        /// any code. Entries are de-duplicated by slot VA — so a call through every
        /// app module's own import table is captured — rather than by resolved
        /// target. Read-only against the target.
        /// </summary>
        public static SlotResult DiscoverImportSlots(TargetProcess process, ModuleMap map)
        {
            var result = new SlotResult();

            string winDir = "";
            try { winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows); }
            catch { /* leave empty: nothing classified system, safe no-op */ }

            int ptr = process.Is64Bit ? 8 : 4;
            byte[] slot = new byte[ptr];

            var seenSlots = new HashSet<ulong>();
            var apiModules = new Dictionary<ulong, ModuleInfo>();

            foreach (var module in map.Modules)
            {
                if (IsSystemModule(module, winDir)) continue;
                if (module.Size == 0) continue;
                if (module.Size > (ulong)MaxModuleImageBytes) { result.SkippedLargeModules++; continue; }

                byte[]? image = ReadImage(process, module);
                if (image == null) continue;

                PeImage pe;
                try { pe = PeImage.FromMappedImage(image, module.BaseAddress); }
                catch { continue; }

                List<PeImport> imports;
                try { imports = pe.ReadImports(); }
                catch { continue; }

                if (imports.Count > 0) result.ScannedModules.Add(module);

                foreach (var imp in imports)
                {
                    string func = imp.ByOrdinal ? "#" + imp.Ordinal : imp.Name!;
                    if (HotPrimitives.Contains(func)) { result.ExcludedHot++; continue; }

                    ulong slotVa = module.BaseAddress + imp.IatRva;
                    if (!seenSlots.Add(slotVa)) continue; // each slot once

                    int n = process.ReadMemory(slotVa, slot);
                    if (n < ptr) continue;
                    ulong target = ptr == 8 ? BitConverter.ToUInt64(slot, 0) : BitConverter.ToUInt32(slot, 0);
                    if (target == 0) continue;

                    var owner = map.Resolve(target);
                    if (owner == null || !IsSystemModule(owner, winDir)) continue;

                    string declared = TrimDllExtension(imp.ModuleName);
                    string label = declared.Length > 0 ? declared + "!" + func : func;
                    result.Slots.Add(new ImportSlot
                    {
                        SlotVa = slotVa,
                        Target = target,
                        OwnerBase = owner.BaseAddress,
                        Label = label,
                    });
                    apiModules[owner.BaseAddress] = owner;

                    if (result.Slots.Count >= MaxEntries) break;
                }
                if (result.Slots.Count >= MaxEntries) break;
            }

            foreach (var m in apiModules.Values) result.ApiModules.Add(m);
            result.Slots.Sort((a, b) => string.Compare(a.Label, b.Label, StringComparison.OrdinalIgnoreCase));
            return result;
        }

        private static bool IsSystemModule(ModuleInfo m, string winDir)
        {
            if (winDir.Length == 0 || string.IsNullOrEmpty(m.Path)) return false;
            return m.Path!.StartsWith(winDir, StringComparison.OrdinalIgnoreCase);
        }

        // Read a module's mapped image into a managed buffer, chunked so an
        // unreadable page (guard page, decommitted region) leaves a zero gap
        // instead of failing the whole read. The import table, lookup thunks and
        // name strings all live within the image, addressed by RVA == offset.
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
