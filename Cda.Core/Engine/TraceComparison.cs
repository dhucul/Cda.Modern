using System;
using System.Collections.Generic;
using Cda.Core.Model;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    public enum TraceDiffStatus
    {
        /// <summary>Observed in both traces, the same number of times.</summary>
        Same,
        /// <summary>Observed in both traces, but a different number of times.</summary>
        Changed,
        /// <summary>Observed in trace A only.</summary>
        OnlyA,
        /// <summary>Observed in trace B only.</summary>
        OnlyB,
    }

    /// <summary>
    /// A function's place in the two traces' first-call <em>sequences</em>, classified
    /// by a longest-common-subsequence alignment (so it is robust to the rank cascade
    /// that a simple rank comparison suffers when functions are added/removed).
    /// </summary>
    public enum SeqOrderClass
    {
        /// <summary>Called in both, and part of the preserved common ordering — not reordered.</summary>
        InOrder,
        /// <summary>Called in both, but genuinely reordered (not in the longest common subsequence).</summary>
        Moved,
        /// <summary>Called in trace A only (dropped from B's flow).</summary>
        Removed,
        /// <summary>Called in trace B only (new in B's flow).</summary>
        Inserted,
    }

    /// <summary>One function's call-count difference between two traces.</summary>
    public sealed class FunctionDiff
    {
        /// <summary>The stable identity the two traces were matched on.</summary>
        public string Key = "";
        /// <summary>Human-readable label (function name, or <c>module+0xRVA</c>).</summary>
        public string Label = "";
        /// <summary>Owning module name (display case), or empty if unknown.</summary>
        public string Module = "";

        /// <summary>Entry address in trace A, or 0 if the function is only in B.</summary>
        public ulong AddressA;
        /// <summary>Entry address in trace B, or 0 if the function is only in A.</summary>
        public ulong AddressB;

        public long CountA;
        public long CountB;

        /// <summary>B minus A: positive = called more in B (or new in B); negative = fewer / removed.</summary>
        public long Delta => CountB - CountA;
        public long AbsDelta => Math.Abs(Delta);

        public TraceDiffStatus Status;

        /// <summary>1-based rank of this function's <em>first</em> call in trace A (the order
        /// functions were first hit), or 0 if it was never called in A.</summary>
        public int RankA;
        /// <summary>1-based first-call rank in trace B, or 0 if never called in B.</summary>
        public int RankB;

        /// <summary>How this function sits in the two first-call sequences (LCS-aligned).</summary>
        public SeqOrderClass SeqOrder;
    }

    /// <summary>
    /// One caller→callee edge's call-count difference between two traces — i.e. how
    /// often the relationship "<c>caller</c> calls <c>callee</c>" fired in A vs B.
    /// </summary>
    public sealed class EdgeDiff
    {
        public string CallerKey = "";
        public string CalleeKey = "";
        public string CallerLabel = "";
        public string CalleeLabel = "";
        /// <summary>Caller's entry address in trace A, or 0 if not present in A.</summary>
        public ulong CallerAddrA;
        /// <summary>Callee's entry address in trace A, or 0 if not present in A.</summary>
        public ulong CalleeAddrA;

        public long CountA;
        public long CountB;
        public long Delta => CountB - CountA;
        public long AbsDelta => Math.Abs(Delta);

        public TraceDiffStatus Status;
    }

    /// <summary>
    /// One decoded string argument's occurrence-count difference between two traces —
    /// how many times that exact string was passed as an argument to any hooked call
    /// in A vs B. Surfaces content (file paths, registry keys, URLs, format strings)
    /// that one run touched and the other didn't.
    /// </summary>
    public sealed class StringArgDiff
    {
        public string Value = "";
        public long CountA;
        public long CountB;
        public long Delta => CountB - CountA;
        public long AbsDelta => Math.Abs(Delta);
        public TraceDiffStatus Status;

        /// <summary>
        /// The functions that received this string as an argument — i.e. <em>where</em> it
        /// was passed — each with its A vs B occurrence count, sorted by |Delta| descending.
        /// A site's identity is the hooked callee (each record's <see cref="CallRecord.Destination"/>),
        /// so navigating to it and centring the butterfly graph reveals which functions passed
        /// the string and how that changed between the runs.
        /// </summary>
        public List<StringSiteDiff> Sites = new();

        /// <summary>
        /// True when some receiving function's count changed between the runs even though the
        /// overall occurrence count did not — i.e. the string moved between call sites. Lets a
        /// "differences only" view keep a row whose <em>where</em> changed but whose total held.
        /// </summary>
        public bool SitesChanged
        {
            get
            {
                foreach (var s in Sites)
                    if (s.Status != TraceDiffStatus.Same) return true;
                return false;
            }
        }
    }

    /// <summary>
    /// One callee that received a given string argument, and how many times it did so in
    /// trace A vs B — the <em>where</em> behind a <see cref="StringArgDiff"/>.
    /// </summary>
    public sealed class StringSiteDiff
    {
        /// <summary>Human-readable callee label (function name, or <c>module+0xRVA</c>).</summary>
        public string Label = "";
        /// <summary>Owning module name (display case), or empty if unknown.</summary>
        public string Module = "";
        /// <summary>Callee entry address in trace A, or 0 if it only received the string in B.</summary>
        public ulong AddressA;
        /// <summary>Callee entry address in trace B, or 0 if it only received the string in A.</summary>
        public ulong AddressB;

        public long CountA;
        public long CountB;
        public long Delta => CountB - CountA;
        public long AbsDelta => Math.Abs(Delta);
        public TraceDiffStatus Status;
    }

    /// <summary>The full result of comparing two traces, plus headline tallies.</summary>
    public sealed class TraceComparisonResult
    {
        /// <summary>One entry per function called in either trace, sorted by |Delta| descending.</summary>
        public List<FunctionDiff> Functions = new();

        /// <summary>One entry per caller→callee edge seen in either trace, sorted by |Delta| descending.</summary>
        public List<EdgeDiff> Edges = new();

        /// <summary>One entry per distinct decoded string argument seen in either trace, sorted by |Delta| descending.</summary>
        public List<StringArgDiff> StringArgs = new();

        public int OnlyACount;
        public int OnlyBCount;
        public int ChangedCount;
        public int SameCount;

        public int EdgeOnlyACount;
        public int EdgeOnlyBCount;
        public int EdgeChangedCount;

        public int StringOnlyACount;
        public int StringOnlyBCount;
        public int StringChangedCount;

        public long TotalCallsA;
        public long TotalCallsB;

        /// <summary>Functions whose call count differs (Changed + OnlyA + OnlyB).</summary>
        public int DifferingCount => ChangedCount + OnlyACount + OnlyBCount;

        /// <summary>Edges whose call count differs (Changed + OnlyA + OnlyB).</summary>
        public int EdgeDifferingCount => EdgeChangedCount + EdgeOnlyACount + EdgeOnlyBCount;

        /// <summary>String arguments whose occurrence count differs (Changed + OnlyA + OnlyB).</summary>
        public int StringDifferingCount => StringChangedCount + StringOnlyACount + StringOnlyBCount;
    }

    /// <summary>
    /// Compares two captured traces by what each one actually <em>executed</em> — the
    /// observed call count of every function and of every caller→callee edge — and
    /// reports where they diverge. The behavioural diff between two runs (e.g. two
    /// inputs, or before / after a change): which functions / relationships ran only
    /// in one, and which ran a different number of times.
    ///
    /// Counts come from the records (tallied by callee entry, which is what a hook
    /// records as <see cref="CallRecord.Destination"/>; the caller is each record's
    /// return address floored to its enclosing function), so it works identically on
    /// a live capture and a reopened <c>.cdatrace</c>.
    ///
    /// Functions are matched in two passes: <b>by module + RVA</b> first — the exact
    /// identity within the same binary, invariant under ASLR and under symbol
    /// availability — then <b>by module + name</b> for whatever is still unpaired, so
    /// the same function in two different builds (RVA shifted, name stable) still
    /// lines up. Edges reuse that same A↔B identity for both endpoints, so the edge
    /// diff is consistent with the function diff.
    /// </summary>
    public static class TraceComparison
    {
        public static TraceComparisonResult Compare(TraceDataset a, TraceDataset b)
        {
            var sideA = Tally(a);
            var sideB = Tally(b);

            // Index B for the two-phase join.
            var bByRva = new Dictionary<string, Side>(sideB.Count);
            var bByName = new Dictionary<string, Side>(sideB.Count);
            foreach (var s in sideB)
            {
                bByRva[s.RvaKey] = s;
                if (s.NameKey != null) bByName[s.NameKey] = s; // last wins on a duplicate name
            }

            var result = new TraceComparisonResult();
            var pairedB = new HashSet<Side>();

            // Pass over A: pair each entry with B by RVA, then by name.
            foreach (var ea in sideA)
            {
                Side? eb = null;
                if (bByRva.TryGetValue(ea.RvaKey, out var byRva) && !pairedB.Contains(byRva))
                    eb = byRva;
                else if (ea.NameKey != null && bByName.TryGetValue(ea.NameKey, out var byName) && !pairedB.Contains(byName))
                    eb = byName;

                if (eb != null) pairedB.Add(eb);
                result.Functions.Add(MakeDiff(ea, eb));
            }

            // Whatever in B never got paired is "only in B".
            foreach (var eb in sideB)
                if (!pairedB.Contains(eb))
                    result.Functions.Add(MakeDiff(null, eb));

            foreach (var d in result.Functions)
            {
                switch (d.Status)
                {
                    case TraceDiffStatus.OnlyA: result.OnlyACount++; break;
                    case TraceDiffStatus.OnlyB: result.OnlyBCount++; break;
                    case TraceDiffStatus.Changed: result.ChangedCount++; break;
                    default: result.SameCount++; break;
                }
                result.TotalCallsA += d.CountA;
                result.TotalCallsB += d.CountB;
            }

            // First-call order: rank each function by when it was first called in each
            // trace, and attach both ranks to its diff (0 = never called in that trace).
            var rankA = FirstCallRanks(a);
            var rankB = FirstCallRanks(b);
            foreach (var d in result.Functions)
            {
                if (d.AddressA != 0 && rankA.TryGetValue(d.AddressA, out int ra)) d.RankA = ra;
                if (d.AddressB != 0 && rankB.TryGetValue(d.AddressB, out int rb)) d.RankB = rb;
            }
            ClassifyFirstCallOrder(result.Functions);

            SortByDelta(result.Functions);

            // Edge-level diff. Endpoints are keyed by module+RVA (name-independent and
            // ASLR-invariant), so the same caller→callee relationship lines up across
            // two runs of the same binary regardless of which functions were named or
            // whether an endpoint was itself ever called.
            result.Edges = CompareEdges(a, b, result);

            // String-argument diff: which decoded string values were passed as call
            // arguments in one run but not the other (matched on the string itself).
            result.StringArgs = CompareStringArgs(a, b, result);

            return result;
        }

        private static void SortByDelta(List<FunctionDiff> list) =>
            list.Sort((x, y) =>
            {
                int c = y.AbsDelta.CompareTo(x.AbsDelta);
                return c != 0 ? c : string.Compare(x.Label, y.Label, StringComparison.OrdinalIgnoreCase);
            });

        private static FunctionDiff MakeDiff(Side? ea, Side? eb)
        {
            // At least one side is non-null. Prefer A for the label/identity (it's the
            // entry the current views can navigate to); fall back to B.
            var src = ea ?? eb!;
            var diff = new FunctionDiff
            {
                Key = src.NameKey ?? src.RvaKey,
                Label = src.Label,
                Module = src.Module,
            };
            if (ea != null) { diff.AddressA = ea.Address; diff.CountA = ea.Count; }
            if (eb != null) { diff.AddressB = eb.Address; diff.CountB = eb.Count; }

            diff.Status =
                ea == null ? TraceDiffStatus.OnlyB :
                eb == null ? TraceDiffStatus.OnlyA :
                ea.Count != eb.Count ? TraceDiffStatus.Changed :
                                       TraceDiffStatus.Same;
            return diff;
        }

        // --- edge-level diff -------------------------------------------------

        private static List<EdgeDiff> CompareEdges(TraceDataset a, TraceDataset b, TraceComparisonResult result)
        {
            // Shared endpoint display info, keyed by RVA key; A is tallied first so its
            // label + A-address win.
            var endpoints = new Dictionary<string, (string label, ulong addrA)>();

            var tA = TallyEdges(a, endpoints, isA: true);
            var tB = TallyEdges(b, endpoints, isA: false);

            var keys = new HashSet<string>(tA.Keys);
            keys.UnionWith(tB.Keys);

            var edges = new List<EdgeDiff>(keys.Count);
            foreach (var key in keys)
            {
                tA.TryGetValue(key, out var ea);
                tB.TryGetValue(key, out var eb);
                var present = ea ?? eb!;

                endpoints.TryGetValue(present.CallerCanon, out var caller);
                endpoints.TryGetValue(present.CalleeCanon, out var callee);

                var e = new EdgeDiff
                {
                    CallerKey = present.CallerCanon,
                    CalleeKey = present.CalleeCanon,
                    CallerLabel = caller.label ?? present.CallerCanon,
                    CalleeLabel = callee.label ?? present.CalleeCanon,
                    CallerAddrA = caller.addrA,
                    CalleeAddrA = callee.addrA,
                    CountA = ea?.Count ?? 0,
                    CountB = eb?.Count ?? 0,
                };
                e.Status =
                    ea == null ? TraceDiffStatus.OnlyB :
                    eb == null ? TraceDiffStatus.OnlyA :
                    ea.Count != eb.Count ? TraceDiffStatus.Changed :
                                           TraceDiffStatus.Same;

                switch (e.Status)
                {
                    case TraceDiffStatus.OnlyA: result.EdgeOnlyACount++; break;
                    case TraceDiffStatus.OnlyB: result.EdgeOnlyBCount++; break;
                    case TraceDiffStatus.Changed: result.EdgeChangedCount++; break;
                }
                edges.Add(e);
            }

            edges.Sort((x, y) =>
            {
                int c = y.AbsDelta.CompareTo(x.AbsDelta);
                if (c != 0) return c;
                int cc = string.Compare(x.CalleeLabel, y.CalleeLabel, StringComparison.OrdinalIgnoreCase);
                return cc != 0 ? cc : string.Compare(x.CallerLabel, y.CallerLabel, StringComparison.OrdinalIgnoreCase);
            });
            return edges;
        }

        private sealed class EdgeAgg
        {
            public string CallerCanon = "";
            public string CalleeCanon = "";
            public long Count;
        }

        private static Dictionary<string, EdgeAgg> TallyEdges(
            TraceDataset ds, Dictionary<string, (string label, ulong addrA)> endpoints, bool isA)
        {
            var map = new ModuleMap(ds.Modules);
            var byAddr = new Dictionary<ulong, TracedFunction>();
            foreach (var f in ds.Functions) byAddr[f.Address] = f;

            // Sorted function entry addresses, to floor a return address to its
            // enclosing function (mirrors the call-graph's caller resolution).
            var entries = new ulong[ds.Functions.Count];
            for (int i = 0; i < ds.Functions.Count; i++) entries[i] = ds.Functions[i].Address;
            Array.Sort(entries);

            var tally = new Dictionary<string, EdgeAgg>();
            foreach (var r in ds.Records)
            {
                ulong callerEntry = FloorEntry(entries, r.Source);
                string callerKey = EndpointKey(map, byAddr, callerEntry, endpoints, isA);
                string calleeKey = EndpointKey(map, byAddr, r.Destination, endpoints, isA);

                string ekey = callerKey + "\n" + calleeKey; // '\n' can't occur in a key
                if (!tally.TryGetValue(ekey, out var agg))
                {
                    agg = new EdgeAgg { CallerCanon = callerKey, CalleeCanon = calleeKey };
                    tally[ekey] = agg;
                }
                agg.Count++;
            }
            return tally;
        }

        // An edge endpoint's identity: its module+RVA key, name-independent so the same
        // function lines up across two runs of one binary whether or not it was named or
        // ever itself called. Records the endpoint's label/A-address the first time it's
        // seen (A first, so A's label and entry address win).
        private static string EndpointKey(
            ModuleMap map, Dictionary<ulong, TracedFunction> byAddr,
            ulong addr, Dictionary<string, (string label, ulong addrA)> endpoints, bool isA)
        {
            var id = Identify(map, byAddr, addr);
            if (!endpoints.ContainsKey(id.rvaKey))
                endpoints[id.rvaKey] = (id.label, isA ? addr : 0);
            return id.rvaKey;
        }

        private static ulong FloorEntry(ulong[] sortedEntries, ulong addr)
        {
            if (sortedEntries.Length == 0) return addr;
            int i = Array.BinarySearch(sortedEntries, addr);
            if (i >= 0) return sortedEntries[i];
            i = ~i - 1;                       // predecessor
            return i >= 0 ? sortedEntries[i] : addr;
        }

        // --- first-call order ------------------------------------------------

        // Maps each called function (by callee entry) to its 1-based first-call rank:
        // 1 for the first distinct function called in the trace, 2 for the next, … —
        // by record time, so it doesn't depend on the records already being ordered.
        private static Dictionary<ulong, int> FirstCallRanks(TraceDataset ds)
        {
            int n = ds.Records.Count;
            var order = new int[n];
            for (int i = 0; i < n; i++) order[i] = i;
            Array.Sort(order, (x, y) => ds.Records[x].Time.CompareTo(ds.Records[y].Time));

            var rank = new Dictionary<ulong, int>();
            int next = 1;
            foreach (int i in order)
            {
                ulong dest = ds.Records[i].Destination;
                if (!rank.ContainsKey(dest)) rank[dest] = next++;
            }
            return rank;
        }

        // Classify each function's place in the two first-call sequences. A simple
        // rank comparison mislabels everything after an added/removed function as
        // "moved" (the rank cascade). Instead we align the sequences by their longest
        // common subsequence: a function in the LCS kept its relative order ("in
        // order"); a common function outside it was genuinely reordered ("moved").
        //
        // Each function appears exactly once per first-call sequence, so the two are
        // permutations of overlapping sets and the LCS equals the longest increasing
        // subsequence of the common functions' B-ranks taken in A-rank order — O(k log k).
        private static void ClassifyFirstCallOrder(List<FunctionDiff> functions)
        {
            // Membership first: only-A = Removed, only-B = Inserted, in-both = Moved
            // (refined to InOrder below for the aligned subsequence).
            foreach (var d in functions)
            {
                bool inA = d.RankA > 0, inB = d.RankB > 0;
                d.SeqOrder = !inA ? SeqOrderClass.Inserted
                           : !inB ? SeqOrderClass.Removed
                                  : SeqOrderClass.Moved;
            }

            // Common functions in A-rank order.
            var common = new List<FunctionDiff>();
            foreach (var d in functions) if (d.RankA > 0 && d.RankB > 0) common.Add(d);
            common.Sort((x, y) => x.RankA.CompareTo(y.RankA));
            if (common.Count == 0) return;

            // Longest strictly-increasing subsequence of RankB over `common` (which is
            // in RankA order), with parent links to recover which elements belong to it.
            int n = common.Count;
            var parent = new int[n];
            var tailIdx = new List<int>();   // tailIdx[L-1] = index (in common) of the smallest
            var tailVal = new List<int>();   // tail value of an increasing subsequence of length L
            for (int i = 0; i < n; i++)
            {
                int v = common[i].RankB;
                int lo = 0, hi = tailVal.Count;
                while (lo < hi) { int mid = (lo + hi) >> 1; if (tailVal[mid] < v) lo = mid + 1; else hi = mid; }
                parent[i] = lo > 0 ? tailIdx[lo - 1] : -1;
                if (lo == tailIdx.Count) { tailIdx.Add(i); tailVal.Add(v); }
                else { tailIdx[lo] = i; tailVal[lo] = v; }
            }

            // Walk the chain back from the longest tail; those are the in-order ones.
            for (int k = tailIdx[tailIdx.Count - 1]; k >= 0; k = parent[k])
                common[k].SeqOrder = SeqOrderClass.InOrder;
        }

        // --- string-argument diff -------------------------------------------

        private static List<StringArgDiff> CompareStringArgs(TraceDataset a, TraceDataset b, TraceComparisonResult result)
        {
            var tA = TallyStringArgs(a);
            var tB = TallyStringArgs(b);

            var keys = new HashSet<string>(tA.Keys);
            keys.UnionWith(tB.Keys);

            var list = new List<StringArgDiff>(keys.Count);
            foreach (var v in keys)
            {
                tA.TryGetValue(v, out var sitesA);
                tB.TryGetValue(v, out var sitesB);

                long ca = SumSiteCounts(sitesA);
                long cb = SumSiteCounts(sitesB);
                var d = new StringArgDiff
                {
                    Value = v,
                    CountA = ca,
                    CountB = cb,
                    Status = ca == 0 ? TraceDiffStatus.OnlyB
                           : cb == 0 ? TraceDiffStatus.OnlyA
                           : ca != cb ? TraceDiffStatus.Changed
                                      : TraceDiffStatus.Same,
                    Sites = MergeSites(sitesA, sitesB),
                };
                switch (d.Status)
                {
                    case TraceDiffStatus.OnlyA: result.StringOnlyACount++; break;
                    case TraceDiffStatus.OnlyB: result.StringOnlyBCount++; break;
                    case TraceDiffStatus.Changed: result.StringChangedCount++; break;
                }
                list.Add(d);
            }

            list.Sort((x, y) =>
            {
                int c = y.AbsDelta.CompareTo(x.AbsDelta);
                return c != 0 ? c : string.Compare(x.Value, y.Value, StringComparison.OrdinalIgnoreCase);
            });
            return list;
        }

        private sealed class SiteAgg
        {
            public string Label = "";
            public string Module = "";
            public ulong Address;   // callee entry address in this trace
            public long Count;
        }

        private static long SumSiteCounts(Dictionary<string, SiteAgg>? sites)
        {
            if (sites == null) return 0;
            long total = 0;
            foreach (var s in sites.Values) total += s.Count;
            return total;
        }

        // Merge one string's per-callee tallies from A and B into the diff site list,
        // keyed by the callee's module+RVA identity (ASLR-invariant), so the same
        // receiving function lines up across the two runs.
        private static List<StringSiteDiff> MergeSites(
            Dictionary<string, SiteAgg>? sitesA, Dictionary<string, SiteAgg>? sitesB)
        {
            var keys = new HashSet<string>();
            if (sitesA != null) keys.UnionWith(sitesA.Keys);
            if (sitesB != null) keys.UnionWith(sitesB.Keys);

            var list = new List<StringSiteDiff>(keys.Count);
            foreach (var k in keys)
            {
                SiteAgg? sa = null, sb = null;
                sitesA?.TryGetValue(k, out sa);
                sitesB?.TryGetValue(k, out sb);
                var present = sa ?? sb!; // at least one side is non-null

                var sd = new StringSiteDiff
                {
                    Label = present.Label,
                    Module = present.Module,
                    AddressA = sa?.Address ?? 0,
                    AddressB = sb?.Address ?? 0,
                    CountA = sa?.Count ?? 0,
                    CountB = sb?.Count ?? 0,
                    Status = sa == null ? TraceDiffStatus.OnlyB
                           : sb == null ? TraceDiffStatus.OnlyA
                           : sa.Count != sb.Count ? TraceDiffStatus.Changed
                                                  : TraceDiffStatus.Same,
                };
                list.Add(sd);
            }

            list.Sort((x, y) =>
            {
                int c = y.AbsDelta.CompareTo(x.AbsDelta);
                if (c != 0) return c;
                int cc = y.CountB.CompareTo(x.CountB);
                return cc != 0 ? cc : string.Compare(x.Label, y.Label, StringComparison.OrdinalIgnoreCase);
            });
            return list;
        }

        // Occurrence count of every decoded string argument in one trace, broken down by
        // the callee that received it: each record's pointer-dereferenced string values
        // (host-side enrichment), tallied by value then by callee identity. A record may
        // carry several string args; each occurrence counts once, attributed to that
        // record's callee (the hooked function it was passed to).
        private static Dictionary<string, Dictionary<string, SiteAgg>> TallyStringArgs(TraceDataset ds)
        {
            var map = new ModuleMap(ds.Modules);
            var byAddr = new Dictionary<ulong, TracedFunction>();
            foreach (var f in ds.Functions) byAddr[f.Address] = f;

            var d = new Dictionary<string, Dictionary<string, SiteAgg>>();
            foreach (var r in ds.Records)
            {
                var derefs = r.Dereferences;
                if (derefs == null) continue;

                var id = Identify(map, byAddr, r.Destination); // the callee that received the args
                foreach (var deref in derefs)
                {
                    string? s = deref.AsString();
                    if (string.IsNullOrEmpty(s)) continue;

                    if (!d.TryGetValue(s, out var sites)) { sites = new(); d[s] = sites; }
                    if (!sites.TryGetValue(id.rvaKey, out var agg))
                    {
                        agg = new SiteAgg { Label = id.label, Module = id.module, Address = r.Destination };
                        sites[id.rvaKey] = agg;
                    }
                    agg.Count++;
                }
            }
            return d;
        }

        // --- shared identity -------------------------------------------------

        private sealed class Side
        {
            public ulong Address;
            public long Count;
            public string Label = "";
            public string Module = "";
            public string RvaKey = "";    // module(lower)+0xRVA, or @0xABS when no module is known
            public string? NameKey;       // module(lower)!name, or null when the function is unnamed
        }

        // Observed call count per function for one trace, aggregated by the function's
        // exact within-run identity (module + RVA, which two records to the same callee
        // entry share). Each entry also carries its name key for the fallback match.
        private static List<Side> Tally(TraceDataset ds)
        {
            var map = new ModuleMap(ds.Modules);
            var byAddr = new Dictionary<ulong, TracedFunction>();
            foreach (var f in ds.Functions) byAddr[f.Address] = f;

            var byRva = new Dictionary<string, Side>();
            foreach (var r in ds.Records)
            {
                var id = Identify(map, byAddr, r.Destination);
                if (!byRva.TryGetValue(id.rvaKey, out var side))
                {
                    side = new Side
                    {
                        Address = r.Destination,
                        Label = id.label,
                        Module = id.module,
                        RvaKey = id.rvaKey,
                        NameKey = id.nameKey,
                    };
                    byRva[id.rvaKey] = side;
                }
                side.Count++;
            }
            return new List<Side>(byRva.Values);
        }

        // The stable identity of an address: its module+RVA key (ASLR-invariant), an
        // optional module!name key, a display label, and the module name.
        private static (string rvaKey, string? nameKey, string label, string module) Identify(
            ModuleMap map, Dictionary<ulong, TracedFunction> byAddr, ulong addr)
        {
            var mod = map.Resolve(addr);
            byAddr.TryGetValue(addr, out var fn);
            string? name = fn?.Name;
            string moduleDisp = mod?.Name ?? "";
            string moduleLower = moduleDisp.ToLowerInvariant();

            string rvaKey, label;
            if (mod != null)
            {
                ulong rva = addr - mod.BaseAddress;
                rvaKey = moduleLower + "+0x" + rva.ToString("x");
                // Prefer a real name for the label; otherwise the stable module+RVA
                // (not the synthetic sub_<absolute>, which differs across runs).
                label = !string.IsNullOrEmpty(name)
                    ? name!
                    : (moduleDisp.Length > 0 ? moduleDisp : "?") + "+0x" + rva.ToString("X");
            }
            else
            {
                rvaKey = "@0x" + addr.ToString("x");
                label = !string.IsNullOrEmpty(name) ? name! : "0x" + addr.ToString("X");
            }

            string? nameKey = !string.IsNullOrEmpty(name) ? moduleLower + "!" + name : null;
            return (rvaKey, nameKey, label, moduleDisp);
        }
    }
}
