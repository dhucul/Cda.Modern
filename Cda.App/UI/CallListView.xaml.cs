using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using Cda.Core.Engine;
using Cda.Core.Model;
using Cda.Core.Process;

namespace Cda.App.UI
{
    /// <summary>
    /// A live, scrollable log of captured calls — caller → callee, integer
    /// arguments, and any decoded string dereferences. Rows are appended as
    /// capture polls arrive, so the trace is readable in-app (no clipboard).
    /// </summary>
    public partial class CallListView : UserControl
    {
        public sealed class CallRow
        {
            public string Seq { get; set; } = "";       // display text (also searched)
            public long SeqNum { get; set; }             // numeric sort key for the "#" column
            public string Time { get; set; } = "";
            public string Source { get; set; } = "";
            public string Dest { get; set; } = "";
            public string Args { get; set; } = "";
            public string Strings { get; set; } = "";
            public bool Bookmarked { get; set; }
            public CallRecord Record { get; set; } = null!;
        }

        private readonly ObservableCollection<CallRow> _rows = new();
        private readonly List<CallRecord> _records = new(); // parallel to _rows, for selection
        private ModuleMap? _map;
        private Func<ulong, string?>? _nameOf; // callee address -> real (API/export) name, if any
        private long _seq;
        private int _maxRows; // 0 = unlimited (keep every call)
        private ICollectionView? _view; // filtered view over _rows (search + bookmarks)
        private string _filterText = "";
        private bool _bookmarkedOnly;
        private bool _selecting; // suppress the selection event during a programmatic jump

        /// <summary>
        /// Raised whenever a call becomes the current selection — by a user row
        /// click, or by a programmatic jump (function click, timeline scrub). Drives
        /// the hex view and call-stack, which should follow every selection source.
        /// </summary>
        public event EventHandler<CallRecord>? CallSelected;

        /// <summary>
        /// Raised only when the user actually clicks a row in the log (never on a
        /// programmatic jump). Lets a host sync to a deliberate row pick without the
        /// timeline scrub or a function-click round-trip also triggering it.
        /// </summary>
        public event EventHandler<CallRecord>? CallClicked;

        public CallListView()
        {
            InitializeComponent();
            Grid.ItemsSource = _rows;
            _view = CollectionViewSource.GetDefaultView(_rows);
            _view.Filter = FilterRow;
            Grid.SelectionChanged += OnSelectionChanged;
            GridCopy.Enable(Grid);
        }

        public void Configure(ModuleMap? map) => _map = map;

        /// <summary>
        /// Supply a resolver from a callee address to its real (exported / Windows
        /// API) name. Used to label calls as <c>module!Name</c> and to pick a Win32
        /// signature for typed argument display; return null for synthetic names.
        /// </summary>
        public void SetNameResolver(Func<ulong, string?>? nameOf) => _nameOf = nameOf;

        public void Clear()
        {
            _rows.Clear();
            _records.Clear();
            _seq = 0;
            Header.Text = "No calls captured yet.";
        }

        /// <summary>
        /// Highlight (and scroll to) the most recent logged call whose callee is
        /// <paramref name="destination"/>. Returns false if no such call is logged
        /// (never called, or it dropped off the "Keep last" cap). Selecting the row
        /// raises CallSelected, which navigates the hex view to the callee.
        /// </summary>
        public bool SelectLastFor(ulong destination)
        {
            for (int i = _records.Count - 1; i >= 0; i--)
            {
                if (_records[i].Destination == destination)
                {
                    // Pause tailing so jumping to an older call (e.g. a startup
                    // call near the top) isn't immediately undone by the next
                    // poll's auto-scroll. Re-check "Follow" to resume tailing.
                    FollowTail.IsChecked = false;
                    Select(i);
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Select (and scroll to) the logged call closest in time to
        /// <paramref name="time"/> — used by the timeline slider to navigate the
        /// call log. Returns the chosen record, or null if the list is empty.
        /// Selecting the row raises CallSelected (so the hex view follows too).
        /// Pauses "Follow" so a live capture's next poll won't scroll away from it.
        /// </summary>
        public CallRecord? SelectNearestTime(double time)
        {
            if (_records.Count == 0) return null;

            // Rows are appended in capture (time) order, so binary-search by time.
            int lo = 0, hi = _records.Count - 1;
            while (lo < hi)
            {
                int mid = (lo + hi) >> 1;
                if (_records[mid].Time < time) lo = mid + 1; else hi = mid;
            }
            int best = lo;
            if (lo > 0 && Math.Abs(_records[lo - 1].Time - time) <= Math.Abs(_records[lo].Time - time))
                best = lo - 1;

            FollowTail.IsChecked = false;
            Select(best);
            return _records[best];
        }

        public void AddRecords(IReadOnlyList<CallRecord> recs)
        {
            if (recs == null || recs.Count == 0) return;

            foreach (var r in recs)
            {
                _seq++;
                _rows.Add(ToRow(r, _seq));
                _records.Add(r);
            }

            TrimToCap();
            UpdateHeader();

            // Don't fight an active filter/bookmark view by scrolling to a row
            // that may be hidden; tailing resumes when the filter is cleared.
            if (FollowTail.IsChecked == true && _rows.Count > 0 && _filterText.Length == 0 && !_bookmarkedOnly)
                Grid.ScrollIntoView(_rows[_rows.Count - 1]);
        }

        // Drop the oldest rows when a finite "Keep last" cap is set (0 = unlimited).
        // Only the on-screen list is bounded; the full trace is retained elsewhere
        // (timeline, Copy results, and the per-function call counts).
        private void TrimToCap()
        {
            if (_maxRows <= 0) return;
            while (_rows.Count > _maxRows) { _rows.RemoveAt(0); _records.RemoveAt(0); }
        }

        private void UpdateHeader()
        {
            string note = (_filterText.Length > 0 || _bookmarkedOnly) ? " · filtered" : "";
            Header.Text = $"{_seq} call(s) captured" +
                          (_rows.Count < _seq ? $" (showing last {_rows.Count})" : "") + note;
        }

        // "Keep last" box changed. Blank, 0, or non-numeric = unlimited (keep all).
        private void OnCapChanged(object sender, TextChangedEventArgs e)
        {
            _maxRows = (int.TryParse(CapBox.Text, out int n) && n > 0) ? n : 0;
            if (Header == null) return; // a change before the view is fully built
            TrimToCap();
            UpdateHeader();
        }

        private CallRow ToRow(CallRecord r, long seq)
        {
            string? name = _nameOf?.Invoke(r.Destination);

            // Decoded strings indexed by argument, so a signature can inline them.
            Dictionary<int, string>? strByArg = null;
            var strs = new StringBuilder();
            if (r.Dereferences != null)
                foreach (var d in r.Dereferences)
                {
                    string? s = d.AsString();
                    if (s == null) continue;
                    (strByArg ??= new Dictionary<int, string>())[d.ArgumentIndex] = s;
                    if (strs.Length > 0) strs.Append("   ");
                    strs.Append($"arg{d.ArgumentIndex}=\"{s}\"");
                }

            return new CallRow
            {
                Seq = seq.ToString(),
                SeqNum = seq,
                Time = r.Time.ToString("0.000000"),
                Source = Describe(r.Source),
                Dest = DescribeCallee(r.Destination, name),
                Args = FormatArgs(r, name, strByArg),
                Strings = strs.ToString(),
                Record = r,
            };
        }

        // Format the argument list. With a known Win32 signature, each captured
        // argument is shown as name=value (strings quoted, flags/handles as hex);
        // otherwise a plain hex list, still inlining any decoded string. Only the
        // captured arguments are shown; a longer signature ends with an ellipsis.
        private string FormatArgs(CallRecord r, string? name, Dictionary<int, string>? strByArg)
        {
            ulong[] args = r.IntegerArgs ?? Array.Empty<ulong>();
            var sig = ApiSignatures.Lookup(name);
            var sb = new StringBuilder();

            if (sig != null)
            {
                int shown = Math.Min(sig.Length, args.Length);
                for (int i = 0; i < shown; i++)
                {
                    if (i > 0) sb.Append(", ");
                    sb.Append(sig[i].Name).Append('=');
                    if (sig[i].Kind == ApiParamKind.String && strByArg != null && strByArg.TryGetValue(i, out var s))
                        sb.Append('"').Append(s).Append('"');
                    else
                        sb.Append(ApiSignatures.FormatValue(sig[i].Kind, args[i]));
                }
                if (sig.Length > shown) sb.Append(shown > 0 ? ", …" : "…");
                return sb.ToString();
            }

            for (int i = 0; i < args.Length; i++)
            {
                if (i > 0) sb.Append(", ");
                if (strByArg != null && strByArg.TryGetValue(i, out var s))
                    sb.Append('"').Append(s).Append('"');
                else
                    sb.Append("0x").Append(args[i].ToString("X"));
            }
            return sb.ToString();
        }

        // Callee label: "module!Name" when a real name is known, else module+0xRVA.
        private string DescribeCallee(ulong addr, string? name)
        {
            if (!string.IsNullOrEmpty(name))
            {
                string mod = _map?.Resolve(addr)?.Name ?? "";
                return mod.Length > 0 ? $"{mod}!{name}" : name!;
            }
            return Describe(addr);
        }

        private string Describe(ulong a)
        {
            if (_map != null) { try { return _map.Describe(a); } catch { /* fall through */ } }
            return "0x" + a.ToString("X");
        }

        private void OnSelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (_selecting) return; // a programmatic jump fires CallSelected itself
            if (Grid.SelectedItems.Count > 1) return; // multi-select is for copy, not navigation
            if (Grid.SelectedItem is CallRow row && row.Record != null)
            {
                CallSelected?.Invoke(this, row.Record); // hex + call-stack follow
                CallClicked?.Invoke(this, row.Record);  // a deliberate row pick (not a programmatic jump)
            }
        }

        // Programmatically select row <i> (by row object, so it survives the
        // filtered view) and drive CallSelected exactly once — even when an active
        // filter is currently hiding that row, so a function-click or timeline
        // scrub still moves the hex / call-stack views.
        private void Select(int i)
        {
            if (i < 0 || i >= _rows.Count) return;
            _selecting = true;
            try
            {
                Grid.SelectedItem = _rows[i];
                Grid.ScrollIntoView(_rows[i]);
            }
            finally { _selecting = false; }
            CallSelected?.Invoke(this, _records[i]);
        }

        // Search + bookmark filter. A row passes when it is bookmarked (if "★ only"
        // is on) and its caller / callee / arguments / strings contain the filter
        // text (case-insensitive). Empty filter shows everything.
        private bool FilterRow(object o)
        {
            if (o is not CallRow row) return true;
            if (_bookmarkedOnly && !row.Bookmarked) return false;
            if (_filterText.Length == 0) return true;
            return Has(row.Source) || Has(row.Dest) || Has(row.Args) || Has(row.Strings) || Has(row.Seq);

            bool Has(string s) => s != null && s.Contains(_filterText, StringComparison.OrdinalIgnoreCase);
        }

        private void OnFilterChanged(object sender, TextChangedEventArgs e)
        {
            _filterText = FilterBox.Text?.Trim() ?? "";
            _view?.Refresh();
            if (Header != null) UpdateHeader();
        }

        private void OnBookmarkOnlyChanged(object sender, RoutedEventArgs e)
        {
            _bookmarkedOnly = BookmarkOnly.IsChecked == true;
            _view?.Refresh();
            if (Header != null) UpdateHeader();
        }

        // A row's bookmark box was toggled: if "★ only" is active, re-evaluate the
        // filter so a just-unbookmarked row drops out immediately.
        private void OnBookmarkClick(object sender, RoutedEventArgs e)
        {
            if (_bookmarkedOnly) _view?.Refresh();
        }
    }
}
