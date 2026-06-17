using System;
using System.Collections.Generic;
using Cda.Core.Model;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Chooses which discovered functions to instrument for a broad startup trace.
    ///
    /// Two filters shape the set. First, functions are ordered by inbound call-site
    /// count and the hottest few are skipped — the original guard against tiny,
    /// re-entrant runtime primitives. Second, and more precisely, "leaf primitives"
    /// are held back: functions that make no call of their own (char/string ops,
    /// accessors, comparisons) and are either tiny or called from very many sites.
    /// These are the runtime-hot utilities that get called in tight loops and flood
    /// the ring buffer, burying the interesting calls — yet static inbound-count
    /// ordering alone doesn't catch them (a leaf called from one site inside a loop
    /// fires millions of times while ranking low). They are pushed behind the real
    /// routines and only drawn on to fill leftover budget on a small target,
    /// least-referenced first.
    ///
    /// Both signals are static, so this can't perfectly predict runtime hotness; the
    /// adaptive in-capture auto-unhook remains the backstop for any flooder that
    /// still slips into the hooked set.
    ///
    /// Shared by the suspended-EXE launch path, the debug-loop DLL launch path, and
    /// the child-process-follow path so all of them select candidates the same way.
    /// </summary>
    public static class StartupPlan
    {
        // A leaf at or under this estimated byte size is treated as a runtime
        // primitive. Size is estimated as the gap to the next discovered function
        // in the same module (discovery yields entry points, not lengths).
        private const int DefaultSmallLeafBytes = 64;

        // A gap to the next discovered entry larger than this is implausible as a
        // real leaf's size — it almost always means the next function simply wasn't
        // discovered (a hole in the static scan). Such a gap is treated as UNKNOWN
        // size rather than as evidence the function is large-and-safe, because the
        // latter is exactly what let a high-fan-in flooder (a leaf with a big gap
        // after it) stay in the hooked set. With size unknown, the fan-in signal
        // decides.
        private const int GapPlausibleMax = 4096;

        // A leaf called from at least this many static call sites is a widely-used
        // utility (memcmp/strlen/accessor-style) — a flood risk regardless of its
        // estimated size, and the reliable signal when size can't be trusted. This
        // catches diffuse high-fan-in leaves that plain size-by-gap misjudges as
        // large and that never dominate a single poll batch (so the per-batch
        // runtime auto-unhook misses them too).
        private const int HighFanInLeaf = 6;

        public static List<ulong> Candidates(
            List<TracedFunction> funcs, List<(ulong Site, ulong Target)> edges, int skipTop, int max,
            int smallLeafBytes = DefaultSmallLeafBytes, ICollection<ulong>? deprioritized = null)
        {
            var freq = new Dictionary<ulong, int>();
            foreach (var (_, t) in edges) freq[t] = freq.TryGetValue(t, out int c) ? c + 1 : 1;

            var ordered = new List<TracedFunction>(funcs);
            ordered.Sort((a, b) =>
            {
                int fb = freq.TryGetValue(b.Address, out int y) ? y : 0;
                int fa = freq.TryGetValue(a.Address, out int x) ? x : 0;
                return fb.CompareTo(fa);
            });

            // Identify the leaf primitives once, up front (see class summary).
            var primitive = ClassifySmallLeaves(funcs, edges, freq, smallLeafBytes);

            // Partition the freq-ordered functions (still skipping the hottest few,
            // as before): real routines first, primitives held behind them.
            var primaries = new List<ulong>();
            var primitives = new List<ulong>();
            for (int i = Math.Min(skipTop, ordered.Count); i < ordered.Count; i++)
            {
                ulong a = ordered[i].Address;
                if (primitive.Contains(a)) primitives.Add(a);
                else primaries.Add(a);
            }

            var list = new List<ulong>();
            for (int i = 0; i < primaries.Count && list.Count < max; i++)
                list.Add(primaries[i]);

            // Leftover budget (a small target with few real routines): fill with the
            // LEAST-referenced primitives first — the ones least likely to be hammered
            // in a hot loop — so if a primitive must be hooked it's the safest one,
            // and the high-fan-in flooders stay out.
            for (int i = primitives.Count - 1; i >= 0 && list.Count < max; i--)
                list.Add(primitives[i]);

            // Never arm zero hooks: if the filters emptied everything, fall back to
            // the plain freq-ordered sweep.
            if (list.Count == 0)
                for (int i = 0; i < ordered.Count && list.Count < max; i++)
                    list.Add(ordered[i].Address);

            // Report which primitives we kept out (for a diagnostic line).
            if (deprioritized != null)
            {
                var inList = new HashSet<ulong>(list);
                foreach (ulong a in primitives) if (!inList.Contains(a)) deprioritized.Add(a);
            }
            return list;
        }

        /// <summary>
        /// Returns the set of function entry points that are flood-prone "leaf
        /// primitives": they make no outbound direct call AND are either
        /// <em>tiny</em> (estimated size at or under <paramref name="smallBytes"/>)
        /// or <em>widely used</em> (called from many static sites). Leafness is read
        /// from the static edge list (a function is a leaf if no call site falls
        /// within its [start, next) range). Size is the gap to the next discovered
        /// entry in the same module, trusted only when present and plausible (see
        /// <see cref="GapPlausibleMax"/>); when size can't be trusted, fan-in alone
        /// decides — which is what catches diffuse high-fan-in leaves whose size-by-
        /// gap looks large.
        /// </summary>
        private static HashSet<ulong> ClassifySmallLeaves(
            List<TracedFunction> funcs, IEnumerable<(ulong Site, ulong Target)> edges,
            Dictionary<ulong, int> freq, int smallBytes)
        {
            var result = new HashSet<ulong>();
            if (funcs.Count == 0) return result;

            // Flat sorted list of all entry points, for the "which function contains
            // this call site" lookup.
            var starts = new List<ulong>(funcs.Count);
            foreach (var f in funcs) starts.Add(f.Address);
            starts.Sort();

            // A function has an outbound call if some call site lies within its
            // [start, nextStart) range — i.e. the nearest start at or below the site.
            var hasOutbound = new HashSet<ulong>();
            foreach (var (site, _) in edges)
            {
                int idx = UpperBoundIndex(starts, site) - 1;
                if (idx >= 0) hasOutbound.Add(starts[idx]);
            }

            // Group entry points by module and sort, so the gap to the next entry
            // estimates each function's size.
            var byModule = new Dictionary<ulong, List<ulong>>();
            foreach (var f in funcs)
            {
                if (!byModule.TryGetValue(f.ModuleBase, out var l)) { l = new List<ulong>(); byModule[f.ModuleBase] = l; }
                l.Add(f.Address);
            }

            foreach (var kv in byModule)
            {
                var addrs = kv.Value;
                addrs.Sort();
                for (int i = 0; i < addrs.Count; i++)
                {
                    ulong start = addrs[i];
                    if (hasOutbound.Contains(start)) continue; // makes a call -> not a leaf

                    // Estimated size = gap to the next discovered entry, trusted only
                    // when present and plausible. A missing (last in module) or
                    // implausibly large gap is a discovery hole, so size is unknown.
                    bool sizeKnown = i + 1 < addrs.Count;
                    ulong size = sizeKnown ? addrs[i + 1] - start : 0;
                    if (sizeKnown && (size == 0 || size > GapPlausibleMax)) sizeKnown = false;

                    bool tiny = smallBytes > 0 && sizeKnown && size <= (ulong)smallBytes;
                    bool widelyUsed = (freq.TryGetValue(start, out int fc) ? fc : 0) >= HighFanInLeaf;

                    // A leaf is a flood-prone primitive if it's tiny OR widely used.
                    // The fan-in clause also covers the unknown-size case, where it's
                    // the only trustworthy signal.
                    if (tiny || widelyUsed) result.Add(start);
                }
            }
            return result;
        }

        // Index of the first element strictly greater than <value> (std::upper_bound).
        private static int UpperBoundIndex(List<ulong> sorted, ulong value)
        {
            int lo = 0, hi = sorted.Count;
            while (lo < hi)
            {
                int mid = (lo + hi) >> 1;
                if (sorted[mid] <= value) lo = mid + 1; else hi = mid;
            }
            return lo;
        }
    }
}
