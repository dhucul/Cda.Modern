using System;
using System.Collections.Generic;
using Cda.Core.Cpu;
using Cda.Core.Model;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// A live attachment to a target process. The first, safe capability is
    /// <b>passive discovery</b>: attach, enumerate modules, read code, and build
    /// the static call graph — with zero writes into the target. Active
    /// instrumentation (the trampoline/capture path) is a separate, gated step
    /// that builds on the same session.
    /// </summary>
    public sealed class LiveSession : IDisposable
    {
        public TargetProcess Process { get; }
        public ModuleMap Modules { get; }
        public TraceDataset Dataset { get; }
        public bool Is64Bit => Process.Is64Bit;

        private LiveSession(TargetProcess process, ModuleMap modules, TraceDataset dataset)
        {
            Process = process;
            Modules = modules;
            Dataset = dataset;
        }

        /// <summary>
        /// Attach to <paramref name="pid"/> and discover the call graph of the
        /// primary module (and any extra modules named in
        /// <paramref name="extraModuleNames"/>). Read-only.
        /// </summary>
        public static LiveSession Attach(int pid, IEnumerable<string>? extraModuleNames = null)
        {
            var proc = TargetProcess.Attach(pid, forWrite: false);
            try
            {
                var allModules = proc.EnumerateModules();
                var map = new ModuleMap(allModules);
                var arch = CpuArchitectures.For(proc.Is64Bit);

                // Candidate modules to scan: the primary image first, then the
                // rest by descending size. A thin launcher or a managed (.NET)
                // host has almost no direct calls in its main module, so if that
                // yields nothing we fall through to larger modules until we find a
                // graph — capped so we don't sweep every system DLL.
                var candidates = new List<ModuleInfo>();
                if (allModules.Count > 0) candidates.Add(allModules[0]);
                var rest = new List<ModuleInfo>(allModules);
                if (rest.Count > 0) rest.RemoveAt(0);
                rest.Sort((a, b) => b.Size.CompareTo(a.Size));
                candidates.AddRange(rest);

                if (extraModuleNames != null)
                {
                    var wanted = new HashSet<string>(extraModuleNames, StringComparer.OrdinalIgnoreCase);
                    // Float explicitly-requested modules to the front.
                    candidates.Sort((a, b) =>
                        (wanted.Contains(b.Name) ? 1 : 0) - (wanted.Contains(a.Name) ? 1 : 0));
                }

                var functions = new List<TracedFunction>();
                var edges = new List<(ulong Site, ulong Target)>();
                var scanned = new List<ModuleInfo>();

                const int maxModulesToScan = 8;
                int tried = 0;
                foreach (var m in candidates)
                {
                    if (tried >= maxModulesToScan) break;
                    tried++;
                    int before = functions.Count;
                    CallSiteScanner.ScanModule(proc, m, arch, functions, edges);
                    if (functions.Count > before) scanned.Add(m);
                    if (functions.Count > 0) break; // got a graph; keep it focused
                }

                var fallbackModules = allModules.Count > 0
                    ? new List<ModuleInfo> { allModules[0] }
                    : allModules;
                var dataset = BuildDataset(scanned.Count > 0 ? scanned : fallbackModules, functions, edges);

                // Best-effort: name internal functions from any locally available
                // PDBs (no symbol server; exact entry matches only). Never fatal —
                // a target without symbols simply keeps its sub_XXXX labels.
                try { SymbolResolver.NameUnnamed(proc, dataset); } catch { /* symbols are optional */ }

                return new LiveSession(proc, map, dataset);
            }
            catch
            {
                proc.Dispose();
                throw;
            }
        }

        private static TraceDataset BuildDataset(
            List<ModuleInfo> modules, List<TracedFunction> functions, List<(ulong Site, ulong Target)> edges)
        {
            var data = new TraceDataset { TimeStart = 0, TimeEnd = 1 };
            data.Modules.AddRange(modules);
            data.Functions.AddRange(functions);

            // Spread the discovered edges across the synthetic [0,1) span so the
            // timeline and active-window highlighting behave as with a real trace.
            // These are static call *sites*, not timestamped runtime calls — the
            // UI labels them as a discovered graph, not a capture.
            int n = Math.Max(1, edges.Count);
            for (int i = 0; i < edges.Count; i++)
            {
                double t = (double)i / n;
                data.Records.Add(new CallRecord(t, edges[i].Site, edges[i].Target));
            }
            return data;
        }

        public void Dispose() => Process.Dispose();
    }
}
