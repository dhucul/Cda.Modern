using System;
using System.Collections.Generic;
using Cda.Core.Engine;
using Cda.Core.Model;

namespace Cda.App.Model
{
    /// <summary>A function rendered as a node in the call graph.</summary>
    public sealed class GraphNode
    {
        public ulong Address;
        public string DisplayName = "";
        public int ModuleIndex;
        public double X;   // logical position in device-independent units (DIPs)
        public double Y;
        public bool Active; // executed within the current playback window
    }

    /// <summary>A directed call edge that fired within the current window.</summary>
    public readonly struct GraphLink
    {
        public readonly int SourceNode;
        public readonly int DestNode;
        public GraphLink(int source, int dest) { SourceNode = source; DestNode = dest; }
    }

    /// <summary>One caller or callee of a function, with its observed call count.</summary>
    public sealed class CallNeighbor
    {
        public ulong Address;
        public string Name = "";
        public long Count;

        // Diff overlay (set only when the neighbourhood is built in compare mode):
        // the edge's A vs B call counts and how it changed.
        public long CountA;
        public long CountB;
        public TraceDiffStatus DiffStatus;
    }

    /// <summary>
    /// The caller/callee ("butterfly") neighbourhood of one function, aggregated
    /// from the recorded calls: who called it and what it called, with counts.
    /// </summary>
    public sealed class CallNeighborhood
    {
        public ulong Center;
        public string CenterName = "";
        public bool CenterKnown;
        public long TotalIn;
        public long TotalOut;
        public List<CallNeighbor> Callers = new();
        public List<CallNeighbor> Callees = new();
        public bool IsEmpty => Callers.Count == 0 && Callees.Count == 0;

        // Diff overlay (set only in compare mode): the centre function's own A vs B
        // call counts and status. <see cref="IsDiff"/> switches the view's rendering.
        public bool IsDiff;
        public long CenterCountA;
        public long CenterCountB;
        public TraceDiffStatus CenterStatus;
    }

    /// <summary>
    /// Builds and owns the laid-out call graph and answers "what is active in
    /// this time window?". This is the managed, DirectX-free equivalent of the
    /// legacy trio <c>oVisModuleManager</c> + <c>oVisModule</c> + <c>oVisLookup</c>:
    ///   * column-packed module layout (faithful to the original algorithm),
    ///   * address -> node resolution (nearest enclosing function),
    ///   * per-window highlighting of executed nodes and call links.
    /// All coordinates are in DIPs; the WPF view applies pan/zoom on top.
    /// </summary>
    public sealed class CallGraphModel
    {
        // Layout constants (DIPs). Scaled-up from the original pixel values so
        // the graph reads well on high-DPI panels.
        private const double ColumnWidth = 170;
        private const double ColumnGap = 28;
        private const double ModuleGap = 18;
        private const double Margin = 24;
        private const double HeaderHeight = 20;
        private const double NodePitch = 6;     // spacing between node centres
        private const double InnerPad = 12;

        public IReadOnlyList<ModuleInfo> Modules => _modules;
        public IReadOnlyList<GraphNode> Nodes => _nodes;
        public double ContentWidth { get; private set; }
        public double ContentHeight { get; private set; }
        public double TimeStart { get; private set; }
        public double TimeEnd { get; private set; }

        private readonly List<ModuleInfo> _modules = new();
        private readonly List<GraphNode> _nodes = new();
        private readonly Dictionary<ulong, int> _addressToNode = new();
        private List<CallRecord> _records = new();

        // Sorted module base addresses for nearest-module lookup.
        private ulong[] _moduleBases = Array.Empty<ulong>();
        // Sorted function addresses for nearest-function lookup.
        private ulong[] _functionAddrs = Array.Empty<ulong>();

        // The set of nodes currently highlighted, so we can reset cheaply.
        private readonly List<int> _activeNodes = new();
        private readonly List<GraphLink> _activeLinks = new();

        public IReadOnlyList<int> ActiveNodes => _activeNodes;
        public IReadOnlyList<GraphLink> ActiveLinks => _activeLinks;

        public void Load(TraceDataset data)
        {
            _modules.Clear();
            _nodes.Clear();
            _addressToNode.Clear();
            _activeNodes.Clear();
            _activeLinks.Clear();

            _modules.AddRange(data.Modules);
            _records = data.Records;
            TimeStart = data.TimeStart;
            TimeEnd = data.TimeEnd;

            // Group functions by module.
            var byModule = new List<List<TracedFunction>>(_modules.Count);
            for (int i = 0; i < _modules.Count; i++)
                byModule.Add(new List<TracedFunction>());

            foreach (var fn in data.Functions)
            {
                int m = FindModuleIndex(fn.ModuleBase != 0 ? fn.ModuleBase : fn.Address);
                if (m < 0) continue;
                byModule[m].Add(fn);
            }

            BuildLayout(byModule);

            // Build fast lookup arrays.
            _moduleBases = new ulong[_modules.Count];
            for (int i = 0; i < _modules.Count; i++) _moduleBases[i] = _modules[i].BaseAddress;
            Array.Sort(_moduleBases);

            _functionAddrs = new ulong[_nodes.Count];
            for (int i = 0; i < _nodes.Count; i++) _functionAddrs[i] = _nodes[i].Address;
            // _nodes are appended module-by-module; ensure addr lookup is sorted.
            Array.Sort(_functionAddrs);
        }

        private int FindModuleIndex(ulong address)
        {
            int best = -1;
            for (int i = 0; i < _modules.Count; i++)
            {
                if (_modules[i].Contains(address)) return i;
                if (_modules[i].BaseAddress <= address &&
                    (best < 0 || _modules[i].BaseAddress > _modules[best].BaseAddress))
                    best = i;
            }
            return best;
        }

        /// <summary>
        /// Column-packing layout, faithful to the original: each module is placed
        /// into the currently shortest column and its functions are tiled in a
        /// grid inside the module's box.
        /// </summary>
        private void BuildLayout(List<List<TracedFunction>> byModule)
        {
            int numColumns = Math.Max(3, (int)Math.Ceiling(Math.Sqrt(Math.Max(1, _modules.Count))));
            var columnHeights = new double[numColumns];

            int nodesPerRow = Math.Max(1, (int)((ColumnWidth - 2 * InnerPad) / NodePitch));

            for (int m = 0; m < _modules.Count; m++)
            {
                var fns = byModule[m];

                // Shortest column.
                int col = 0;
                for (int c = 1; c < numColumns; c++)
                    if (columnHeights[c] < columnHeights[col]) col = c;

                double x = Margin + col * (ColumnWidth + ColumnGap);
                double y = Margin + columnHeights[col];

                int rows = (fns.Count + nodesPerRow - 1) / nodesPerRow;
                double moduleHeight = HeaderHeight + rows * NodePitch + InnerPad;

                for (int i = 0; i < fns.Count; i++)
                {
                    var node = new GraphNode
                    {
                        Address = fns[i].Address,
                        DisplayName = fns[i].DisplayName,
                        ModuleIndex = m,
                        X = x + InnerPad + (i % nodesPerRow) * NodePitch,
                        Y = y + HeaderHeight + (i / nodesPerRow) * NodePitch,
                        Active = false
                    };
                    int idx = _nodes.Count;
                    _nodes.Add(node);
                    _addressToNode[node.Address] = idx;
                }

                // Remember module box origin via a lightweight record on the
                // ModuleInfo through parallel arrays would be cleaner; for the
                // first slice we recompute label anchors from node bounds in the
                // view, so we only need column heights advanced here.
                columnHeights[col] += moduleHeight + ModuleGap;

                ContentWidth = Math.Max(ContentWidth, x + ColumnWidth + Margin);
            }

            double maxCol = 0;
            foreach (var h in columnHeights) maxCol = Math.Max(maxCol, h);
            ContentHeight = Margin + maxCol;
        }

        /// <summary>
        /// Resolve an arbitrary address to the index of the nearest enclosing
        /// function node, mirroring the original binary-search-to-floor logic.
        /// </summary>
        public int ResolveNode(ulong address)
        {
            if (_addressToNode.TryGetValue(address, out int exact)) return exact;
            if (_functionAddrs.Length == 0) return -1;

            int lo = Array.BinarySearch(_functionAddrs, address);
            if (lo < 0) lo = ~lo - 1;
            if (lo < 0) lo = 0;
            if (lo >= _functionAddrs.Length) lo = _functionAddrs.Length - 1;

            return _addressToNode.TryGetValue(_functionAddrs[lo], out int idx) ? idx : -1;
        }

        /// <summary>
        /// Replace the record set (live capture). Keeps the existing node layout;
        /// only the timeline data changes. Records are sorted by time so the
        /// active-window binary search stays valid.
        /// </summary>
        public void SetRecords(List<CallRecord> records)
        {
            records.Sort((a, b) => a.Time.CompareTo(b.Time));
            _records = records;

            foreach (int n in _activeNodes) _nodes[n].Active = false;
            _activeNodes.Clear();
            _activeLinks.Clear();

            if (records.Count > 0)
            {
                TimeStart = records[0].Time;
                TimeEnd = records[records.Count - 1].Time;
            }
        }

        /// <summary>
        /// Point the model at a live, append-only record list <b>by reference</b>,
        /// without copying or sorting it. The caller owns the list and guarantees it
        /// is (near) time-ordered — a capture drains the ring in call order — so a
        /// live capture never re-copies or re-sorts its whole history on every poll;
        /// it just appends and calls <see cref="SetActiveWindow"/> to refresh the
        /// highlighted tail. Contrast <see cref="SetRecords"/>, which takes ownership
        /// of a one-shot (offline) set and sorts it once.
        /// </summary>
        public void UseLiveRecords(List<CallRecord> records)
        {
            _records = records;

            foreach (int n in _activeNodes) _nodes[n].Active = false;
            _activeNodes.Clear();
            _activeLinks.Clear();

            if (records.Count > 0)
            {
                TimeStart = records[0].Time;
                TimeEnd = records[records.Count - 1].Time;
            }
        }

        /// <summary>
        /// Recompute which nodes/links are active for the half-open time window
        /// [start, end). Equivalent to the per-frame work the legacy
        /// <c>oVisLookup.setData</c> did, but without uploading vertex buffers.
        /// </summary>
        public void SetActiveWindow(double start, double end)
        {
            foreach (int n in _activeNodes) _nodes[n].Active = false;
            _activeNodes.Clear();
            _activeLinks.Clear();

            if (_records == null) return;

            // Records are time-sorted; a binary search bounds the scan.
            int i = LowerBound(start);
            for (; i < _records.Count; i++)
            {
                var r = _records[i];
                if (r.Time >= end) break;

                int s = ResolveNode(r.Source);
                int d = ResolveNode(r.Destination);

                if (s >= 0 && !_nodes[s].Active) { _nodes[s].Active = true; _activeNodes.Add(s); }
                if (d >= 0 && !_nodes[d].Active) { _nodes[d].Active = true; _activeNodes.Add(d); }
                if (s >= 0 && d >= 0) _activeLinks.Add(new GraphLink(s, d));
            }
        }

        private int LowerBound(double time)
        {
            int lo = 0, hi = _records.Count;
            while (lo < hi)
            {
                int mid = (lo + hi) >> 1;
                if (_records[mid].Time < time) lo = mid + 1; else hi = mid;
            }
            return lo;
        }

        public IReadOnlyList<CallRecord> Records => _records;

        /// <summary>
        /// Aggregate the recorded calls around one function into a caller/callee
        /// ("butterfly") neighbourhood: who called <paramref name="center"/> and
        /// what it called, each with an observed-call count. Callers are resolved
        /// from each call's return address to the enclosing function; callees are
        /// exact callee entries. Returns the top <paramref name="maxEach"/> of each
        /// by count. Works for a live capture and for the static call edges of an
        /// opened module alike.
        /// </summary>
        public CallNeighborhood BuildNeighborhood(ulong center, int maxEach = 14)
        {
            var nb = new CallNeighborhood { Center = center };
            int ci = ResolveNode(center);
            if (ci >= 0 && !string.IsNullOrEmpty(_nodes[ci].DisplayName))
            {
                nb.CenterName = _nodes[ci].DisplayName;
                nb.CenterKnown = true;
            }
            else nb.CenterName = "0x" + center.ToString("X");

            var callers = new Dictionary<ulong, long>();
            var callees = new Dictionary<ulong, long>();

            var records = _records;
            for (int i = 0; i < records.Count; i++)
            {
                var r = records[i];
                if (r.Destination == center)
                {
                    // Inbound: someone called the centre. Attribute it to the
                    // caller's enclosing function (resolved from the return address).
                    int s = ResolveNode(r.Source);
                    ulong key = s >= 0 ? _nodes[s].Address : r.Source;
                    callers[key] = callers.TryGetValue(key, out long c) ? c + 1 : 1;
                    nb.TotalIn++;
                }
                else
                {
                    // Outbound: a call whose caller resolves to the centre.
                    int s = ResolveNode(r.Source);
                    if (s >= 0 && _nodes[s].Address == center)
                    {
                        callees[r.Destination] = callees.TryGetValue(r.Destination, out long c) ? c + 1 : 1;
                        nb.TotalOut++;
                    }
                }
            }

            nb.Callers = TopNeighbors(callers, maxEach);
            nb.Callees = TopNeighbors(callees, maxEach);
            return nb;
        }

        private List<CallNeighbor> TopNeighbors(Dictionary<ulong, long> counts, int max)
        {
            var list = new List<CallNeighbor>(counts.Count);
            foreach (var kv in counts)
            {
                int n = ResolveNode(kv.Key);
                string name = (n >= 0 && !string.IsNullOrEmpty(_nodes[n].DisplayName))
                    ? _nodes[n].DisplayName
                    : "0x" + kv.Key.ToString("X");
                list.Add(new CallNeighbor { Address = kv.Key, Name = name, Count = kv.Value });
            }
            list.Sort((a, b) => b.Count.CompareTo(a.Count));
            if (list.Count > max) list.RemoveRange(max, list.Count - max);
            return list;
        }
    }
}
