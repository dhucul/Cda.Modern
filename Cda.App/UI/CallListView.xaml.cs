using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
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
            public string Return { get; set; } = "";
            public string Strings { get; set; } = "";          // single line, for the grid column
            public string StringsMultiline { get; set; } = ""; // one per line, for the detail panel
            public bool HasReturn { get; set; }
            public bool HasStrings { get; set; }
            public bool Bookmarked { get; set; }
            public CallRecord Record { get; set; } = null!;
        }

        // WPF's ObservableCollection raises one CollectionChanged event per Add.
        // A full startup-ring drain can contain 65K calls, and sending 65K events to
        // the DataGrid makes the window appear hung even with row virtualization on.
        // This small derivative mutates a batch silently and raises one Reset event.
        private sealed class BatchObservableCollection<T> : ObservableCollection<T>
        {
            public void ReplaceAll(IReadOnlyList<T> items)
            {
                Items.Clear();
                for (int i = 0; i < items.Count; i++) Items.Add(items[i]);
                NotifyReset();
            }

            public void AppendAll(IReadOnlyList<T> items)
            {
                for (int i = 0; i < items.Count; i++) Items.Add(items[i]);
                NotifyReset();
            }

            private void NotifyReset()
            {
                OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
                OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
                OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
            }
        }

        private const int DefaultMaxRows = 5000;
        private const int BatchResetThreshold = 512;
        private readonly BatchObservableCollection<CallRow> _rows = new();
        private ModuleMap? _map;
        private Func<ulong, string?>? _nameOf; // callee address -> real (API/export) name, if any
        private long _seq;
        private int _maxRows = DefaultMaxRows; // 0 = unlimited (keep every call)
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
            for (int i = _rows.Count - 1; i >= 0; i--)
            {
                if (_rows[i].Record.Destination == destination)
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
        /// Select <paramref name="record"/> if its row is still retained by the
        /// "Keep last" cap. The timeline finds the nearest call from the full trace
        /// first, then uses this method only to synchronize the visible row. Returns
        /// false when the full-trace record has already aged out of the grid.
        /// </summary>
        public bool SelectRecord(CallRecord record)
        {
            FollowTail.IsChecked = false;
            for (int i = 0; i < _rows.Count; i++)
            {
                if (!ReferenceEquals(_rows[i].Record, record)) continue;
                Select(i);
                return true;
            }
            return false;
        }

        public void AddRecords(IReadOnlyList<CallRecord> recs)
        {
            if (recs == null || recs.Count == 0) return;

            long firstSeq = _seq + 1;
            _seq += recs.Count;

            int incomingStart = _maxRows > 0 ? Math.Max(0, recs.Count - _maxRows) : 0;
            int incomingKeep = recs.Count - incomingStart;
            int existingKeep = _maxRows > 0
                ? Math.Min(_rows.Count, _maxRows - incomingKeep)
                : _rows.Count;
            int existingStart = _rows.Count - existingKeep;
            bool useReset = incomingKeep + existingStart >= BatchResetThreshold;
            var selected = Grid.SelectedItem as CallRow;

            if (_maxRows > 0)
            {
                // Retain only enough existing rows to leave room for the newest part
                // of this batch. Crucially, records that cannot fit are never formatted
                // into CallRow objects in the first place.
                if (useReset)
                {
                    var nextRows = new List<CallRow>(existingKeep + incomingKeep);
                    for (int i = existingStart; i < _rows.Count; i++) nextRows.Add(_rows[i]);
                    for (int i = incomingStart; i < recs.Count; i++)
                        nextRows.Add(ToRow(recs[i], firstSeq + i));
                    ReplaceRows(nextRows, selected);
                }
                else
                {
                    MutateRows(() =>
                    {
                        for (int i = 0; i < existingStart; i++) _rows.RemoveAt(0);
                        for (int i = incomingStart; i < recs.Count; i++)
                            _rows.Add(ToRow(recs[i], firstSeq + i));
                    }, selected, scrollSelection: false);
                }
            }
            else
            {
                // Unlimited is an explicit opt-in. Ordinary batches use normal Add
                // notifications so selection, scroll position, sorting, and filtering
                // stay stable; only a genuinely large batch uses one Reset.
                if (useReset)
                {
                    var addedRows = new List<CallRow>(recs.Count);
                    for (int i = 0; i < recs.Count; i++)
                        addedRows.Add(ToRow(recs[i], firstSeq + i));
                    MutateRows(() => _rows.AppendAll(addedRows), selected, scrollSelection: true);
                }
                else
                {
                    MutateRows(() =>
                    {
                        for (int i = 0; i < recs.Count; i++)
                            _rows.Add(ToRow(recs[i], firstSeq + i));
                    }, selected, scrollSelection: false);
                }
            }

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
            if (_maxRows <= 0 || _rows.Count <= _maxRows) return;
            int remove = _rows.Count - _maxRows;
            var kept = new List<CallRow>(_maxRows);
            for (int i = remove; i < _rows.Count; i++) kept.Add(_rows[i]);
            ReplaceRows(kept, Grid.SelectedItem as CallRow);
        }

        private void ReplaceRows(IReadOnlyList<CallRow> rows, CallRow? selected) =>
            MutateRows(() => _rows.ReplaceAll(rows), selected, scrollSelection: true);

        // Collection-change notifications are synchronous. Suppress navigation events
        // while a batch mutates the grid, then restore a retained selection by object
        // identity. Small batches never Reset; large batches preserve the call being
        // inspected and scroll it back into view when Follow is paused.
        private void MutateRows(Action mutation, CallRow? selected, bool scrollSelection)
        {
            CallRow? viewportAnchor = scrollSelection && selected == null && FollowTail.IsChecked != true
                ? FindTopVisibleRow()
                : null;
            _selecting = true;
            try
            {
                mutation();
                if (selected != null && _rows.Contains(selected))
                {
                    Grid.SelectedItem = selected;
                    if (scrollSelection && FollowTail.IsChecked != true)
                        Grid.ScrollIntoView(selected);
                }
                else if (viewportAnchor != null && _rows.Contains(viewportAnchor))
                {
                    // A large Reset invalidates the DataGrid's realized containers.
                    // Keep the formerly topmost visible call in view when the user
                    // paused Follow but had not selected a row.
                    Grid.ScrollIntoView(viewportAnchor);
                }
            }
            finally { _selecting = false; }
        }

        private CallRow? FindTopVisibleRow()
        {
            CallRow? best = null;
            double bestY = double.MaxValue;

            void Visit(DependencyObject parent)
            {
                int count = VisualTreeHelper.GetChildrenCount(parent);
                for (int i = 0; i < count; i++)
                {
                    DependencyObject child = VisualTreeHelper.GetChild(parent, i);
                    if (child is DataGridRow row && row.Item is CallRow item && row.IsVisible)
                    {
                        Point p = row.TranslatePoint(new Point(0, 0), Grid);
                        if (p.Y + row.ActualHeight >= 0 && p.Y < bestY)
                        {
                            bestY = p.Y;
                            best = item;
                        }
                    }
                    Visit(child);
                }
            }

            Visit(Grid);
            return best;
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
            // Built two ways: single-line (space-separated) for the grid column, and
            // one-per-line for the detail panel that unfurls under the selected call.
            Dictionary<int, string>? strByArg = null;
            var strs = new StringBuilder();
            var strsMulti = new StringBuilder();
            if (r.Dereferences != null)
                foreach (var d in r.Dereferences)
                {
                    string? s = d.AsString();
                    if (s == null) continue;
                    (strByArg ??= new Dictionary<int, string>())[d.ArgumentIndex] = s;
                    if (strs.Length > 0) strs.Append("   ");
                    strs.Append($"arg{d.ArgumentIndex}=\"{s}\"");
                    if (strsMulti.Length > 0) strsMulti.Append('\n');
                    strsMulti.Append($"arg{d.ArgumentIndex} = \"{s}\"");
                }

            string ret = FormatReturn(r);

            return new CallRow
            {
                Seq = seq.ToString(),
                SeqNum = seq,
                Time = r.Time.ToString("0.000000"),
                Source = Describe(r.Source),
                Dest = DescribeCallee(r.Destination, name),
                Args = FormatArgs(r, name, strByArg),
                Return = ret,
                Strings = strs.ToString(),
                StringsMultiline = strsMulti.ToString(),
                HasReturn = ret.Length > 0,
                HasStrings = strs.Length > 0,
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

        // Return value column: the integer result (RAX/EAX) once the call has
        // returned, with a decoded string if the value pointed at one. Blank when
        // return capture was off, or while the return is still outstanding. (A return
        // that lands in a later poll than its call updates the record but not this
        // already-built row — most fast calls pair within one poll.)
        private static string FormatReturn(CallRecord r)
        {
            if (!r.HasReturned) return "";
            string s = "0x" + r.ReturnValue.ToString("X");
            string? str = r.ReturnDereference?.AsString();
            return str != null ? $"{s} \"{str}\"" : s;
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
            // Unfurl the per-call detail panel only for a lone selection — a multi-row
            // selection is a copy gesture, so keep those rows compact.
            Grid.RowDetailsVisibilityMode = Grid.SelectedItems.Count == 1
                ? DataGridRowDetailsVisibilityMode.VisibleWhenSelected
                : DataGridRowDetailsVisibilityMode.Collapsed;

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
            CallSelected?.Invoke(this, _rows[i].Record);
        }

        // Search + bookmark filter. A row passes when it is bookmarked (if "★ only"
        // is on) and its caller / callee / arguments / strings contain the filter
        // text (case-insensitive). Empty filter shows everything.
        private bool FilterRow(object o)
        {
            if (o is not CallRow row) return true;
            if (_bookmarkedOnly && !row.Bookmarked) return false;
            if (_filterText.Length == 0) return true;
            return Has(row.Source) || Has(row.Dest) || Has(row.Args) || Has(row.Return) || Has(row.Strings) || Has(row.Seq);

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

        // Scroll the detail's strings box one line per wheel notch (the default is the
        // system's ~3 lines). Handling PreviewMouseWheel replaces the TextBox's own
        // wheel scroll; one line per 120-unit notch (more for a fast/coarse wheel).
        private void OnStringsWheel(object sender, MouseWheelEventArgs e)
        {
            if (sender is not TextBox tb) return;
            if (tb.Template?.FindName("PART_ContentHost", tb) is not ScrollViewer sv) return;

            int lines = Math.Max(1, Math.Abs(e.Delta) / 120);
            for (int i = 0; i < lines; i++)
            {
                if (e.Delta > 0) sv.LineUp();
                else sv.LineDown();
            }
            e.Handled = true;
        }
    }
}
