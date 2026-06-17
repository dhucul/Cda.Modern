using System;
using System.Collections.Generic;
using Cda.Core.Engine;

namespace Cda.App.Model
{
    /// <summary>
    /// Turns an engine <see cref="TraceComparisonResult"/> into diff-annotated
    /// butterfly neighbourhoods for the call graph: for a centre function (addressed
    /// in trace A), its callers are the edges <i>into</i> it and its callees the edges
    /// <i>out of</i> it, each carrying the A vs B call counts and how it changed. This
    /// is what lets the existing butterfly view recolour caller/callee nodes by whether
    /// the relationship appeared, vanished, or fired a different number of times.
    /// </summary>
    public sealed class GraphDiff
    {
        private readonly Dictionary<ulong, string> _aAddrToKey = new();   // A-address -> edge key (RVA key)
        private readonly Dictionary<ulong, string> _aAddrToLabel = new();
        private readonly Dictionary<string, List<EdgeDiff>> _callersOf = new(); // calleeKey -> inbound edges
        private readonly Dictionary<string, List<EdgeDiff>> _calleesOf = new(); // callerKey -> outbound edges

        public GraphDiff(TraceComparisonResult result)
        {
            // Everything is keyed in the edges' RVA-key space, so a selected A-address
            // resolves to exactly the keys the edges are indexed by — and the centre's
            // own counts come from its edges too (see Build), which is exact and works
            // even for a function that has no A-side address (called only in B).
            foreach (var e in result.Edges)
            {
                Register(e.CallerAddrA, e.CallerKey, e.CallerLabel);
                Register(e.CalleeAddrA, e.CalleeKey, e.CalleeLabel);
                Add(_callersOf, e.CalleeKey, e);
                Add(_calleesOf, e.CallerKey, e);
            }
        }

        private void Register(ulong addrA, string key, string label)
        {
            if (addrA == 0 || _aAddrToKey.ContainsKey(addrA)) return;
            _aAddrToKey[addrA] = key;
            _aAddrToLabel[addrA] = label;
        }

        private static void Add(Dictionary<string, List<EdgeDiff>> map, string key, EdgeDiff e)
        {
            if (!map.TryGetValue(key, out var list)) { list = new List<EdgeDiff>(); map[key] = list; }
            list.Add(e);
        }

        /// <summary>
        /// Build the diff neighbourhood for the function at <paramref name="centerAddrA"/>
        /// (an address in trace A). Returns null if that address isn't a function present
        /// in trace A — the view then falls back to its normal (live) rendering, so a
        /// selection made after a fresh capture isn't forced through a stale comparison.
        /// </summary>
        public CallNeighborhood? Build(ulong centerAddrA, int maxEach = 14)
        {
            if (!_aAddrToKey.TryGetValue(centerAddrA, out var key)) return null;

            var nb = new CallNeighborhood { Center = centerAddrA, IsDiff = true };
            nb.CenterName = _aAddrToLabel.TryGetValue(centerAddrA, out var lbl) ? lbl : "0x" + centerAddrA.ToString("X");
            nb.CenterKnown = true;

            _callersOf.TryGetValue(key, out var callers);
            _calleesOf.TryGetValue(key, out var callees);

            // The centre's own "called A→B" counts are the sum over ALL its inbound
            // edges — every call to it is exactly one inbound-edge instance — so this is
            // exact and, unlike a function-diff lookup keyed by A-address, also right for
            // a function that is called only in B (no A-side address). Summed over the
            // full list, before the caller list is trimmed for display.
            long inA = 0, inB = 0;
            if (callers != null)
                foreach (var e in callers) { inA += e.CountA; inB += e.CountB; }
            nb.CenterCountA = inA;
            nb.CenterCountB = inB;
            nb.CenterStatus = inA == inB ? TraceDiffStatus.Same
                            : inA == 0 ? TraceDiffStatus.OnlyB
                            : inB == 0 ? TraceDiffStatus.OnlyA
                                       : TraceDiffStatus.Changed;

            if (callers != null) foreach (var e in callers) nb.Callers.Add(NeighborFor(e, caller: true));
            if (callees != null) foreach (var e in callees) nb.Callees.Add(NeighborFor(e, caller: false));

            Trim(nb.Callers, maxEach);
            Trim(nb.Callees, maxEach);
            return nb;
        }

        private static CallNeighbor NeighborFor(EdgeDiff e, bool caller) => new()
        {
            Address = caller ? e.CallerAddrA : e.CalleeAddrA,
            Name = caller ? e.CallerLabel : e.CalleeLabel,
            CountA = e.CountA,
            CountB = e.CountB,
            Count = Math.Max(e.CountA, e.CountB), // edge weight for the view's bar thickness
            DiffStatus = e.Status,
        };

        // Most-changed neighbours first (by |delta|), then by sheer call volume, so the
        // butterfly shows the relationships that actually moved.
        private static void Trim(List<CallNeighbor> list, int max)
        {
            list.Sort((x, y) =>
            {
                long dx = Math.Abs(x.CountB - x.CountA), dy = Math.Abs(y.CountB - y.CountA);
                int c = dy.CompareTo(dx);
                return c != 0 ? c : Math.Max(y.CountA, y.CountB).CompareTo(Math.Max(x.CountA, x.CountB));
            });
            if (list.Count > max) list.RemoveRange(max, list.Count - max);
        }
    }
}
