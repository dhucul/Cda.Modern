using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using Cda.Core.Model;
using Cda.Core.Process;

namespace Cda.App.UI
{
    /// <summary>
    /// Row view-model for the function grid.
    /// </summary>
    public sealed class FunctionRow : INotifyPropertyChanged
    {
        public ulong Address { get; init; }
        public string AddressHex => "0x" + Address.ToString("X");
        public string Module { get; init; } = "";
        public string Name { get; init; } = "";

        private long _callCount;
        public long CallCount
        {
            get => _callCount;
            init => _callCount = value;
        }

        // Rank in first-call order: 0 for the first function called in the trace, 1 for
        // the next newly-called one, and so on; long.MaxValue until the function is
        // called (so uncalled functions sort to the bottom). This is the sort key for
        // the "Order" column / "Call order" button.
        private long _firstCallSeq = long.MaxValue;
        public long FirstCallSeq => _firstCallSeq;

        /// <summary>Display for the Order column: 1-based rank, or blank if never called.</summary>
        public string CallOrderText =>
            _firstCallSeq == long.MaxValue ? "" : (_firstCallSeq + 1).ToString(CultureInfo.InvariantCulture);

        /// <summary>Stamp this row's first-call rank the first time it is called (idempotent).</summary>
        public void StampFirstCall(long seq)
        {
            if (_firstCallSeq != long.MaxValue) return;
            _firstCallSeq = seq;
            PropertyChanged?.Invoke(this, _firstCallSeqChanged);
            PropertyChanged?.Invoke(this, _callOrderTextChanged);
        }

        /// <summary>Clear the first-call rank (a new capture starting).</summary>
        public void ResetFirstCall()
        {
            if (_firstCallSeq == long.MaxValue) return;
            _firstCallSeq = long.MaxValue;
            PropertyChanged?.Invoke(this, _firstCallSeqChanged);
            PropertyChanged?.Invoke(this, _callOrderTextChanged);
        }

        /// <summary>Add observed calls and refresh this cell in the grid.</summary>
        public void AddCalls(long n)
        {
            if (n == 0) return;
            _callCount += n;
            PropertyChanged?.Invoke(this, _callCountChanged);
        }

        /// <summary>Set the observed-call counter (used to reset between captures).</summary>
        public void SetCalls(long n)
        {
            if (_callCount == n) return;
            _callCount = n;
            PropertyChanged?.Invoke(this, _callCountChanged);
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private static readonly PropertyChangedEventArgs _callCountChanged = new(nameof(CallCount));
        private static readonly PropertyChangedEventArgs _firstCallSeqChanged = new(nameof(FirstCallSeq));
        private static readonly PropertyChangedEventArgs _callOrderTextChanged = new(nameof(CallOrderText));
    }

    /// <summary>
    /// Virtualized function list — the modern replacement for the legacy
    /// <c>FunctionListViewer</c> / DataGridViewEx. Bindable from a
    /// <see cref="TraceDataset"/> (demo or live) or directly from a parsed PE's
    /// exports, with live text filtering.
    /// </summary>
    public partial class FunctionListView : UserControl
    {
        private readonly ObservableCollection<FunctionRow> _rows = new();
        private readonly Dictionary<ulong, FunctionRow> _byAddress = new(); // address -> row, for live count updates
        private readonly ICollectionView _view;
        private bool _suppressSelectionEvent;

        // Call-count filter, layered on top of the text filter. Non-destructive:
        // it only hides rows in the view, so the backing _rows / _byAddress (and
        // thus live counting, the graph, and the dataset) are never touched and
        // "Show all" fully restores the list.
        private enum CountFilterMode { All, NonZero, Exact }
        private CountFilterMode _countMode = CountFilterMode.All;
        private long _countExact;

        // Next first-call rank to hand out. Incremented each time a not-yet-called
        // function is hit for the first time, so the rank reflects the order functions
        // were first called across the whole trace. Reset whenever the list is reloaded
        // or counts are zeroed for a new capture.
        private long _firstCallOrderNext;

        public event EventHandler<ulong>? FunctionSelected;

        /// <summary>
        /// Raised when one of the call-count filter operations runs (Hide 0-hit / Only N
        /// hits / Show all), so a host can mirror the state — e.g. keep a toolbar
        /// "only new" checkbox in lockstep. NOT raised on dataset loads or
        /// <see cref="ResetCounts"/> (which reset to "show all" but must not disturb that
        /// preference), since those don't go through the filter methods below.
        /// </summary>
        public event EventHandler? CountFilterChanged;

        /// <summary>True while the list is hiding never-called functions (Hide 0-hit).</summary>
        public bool IsHidingZeroHit => _countMode == CountFilterMode.NonZero;

        public FunctionListView()
        {
            InitializeComponent();
            _view = CollectionViewSource.GetDefaultView(_rows);
            _view.Filter = FilterRow;
            // Register CallCount for live filtering so "Hide 0-hit" updates as calls
            // arrive: a function that goes from 0 to >0 calls appears the moment it's
            // first called, without re-applying the filter. Live filtering is toggled
            // on only for that mode (see SetLiveFiltering); the other modes stay snapshots.
            if (_view is ICollectionViewLiveShaping shaping)
                shaping.LiveFilteringProperties.Add(nameof(FunctionRow.CallCount));
            Grid.ItemsSource = _view;
            GridCopy.Enable(Grid, selectRowOnRightClick: false); // selecting a function refocuses a live trace
        }

        public void LoadFromDataset(TraceDataset data)
        {
            var map = new ModuleMap(data.Modules);
            _rows.Clear();
            _byAddress.Clear();
            foreach (var fn in data.Functions)
            {
                var mod = map.Resolve(fn.Address);
                var row = new FunctionRow
                {
                    Address = fn.Address,
                    Module = mod?.Name ?? "",
                    Name = fn.Name ?? fn.DisplayName,
                    CallCount = fn.CallCount,
                };
                _rows.Add(row);
                _byAddress[fn.Address] = row;
            }
            _countMode = CountFilterMode.All; // a fresh dataset always starts fully visible
            SetLiveFiltering(false);          // snapshot default until "Hide 0-hit" is applied
            _firstCallOrderNext = 0;          // ranks restart with the new dataset
            _view.SortDescriptions.Clear();   // drop any call-order/column sort; show natural order
            _view.Refresh();
            UpdateMatchInfo();
        }

        public void LoadFunctions(IEnumerable<TracedFunction> functions, ModuleMap? map = null)
        {
            _rows.Clear();
            _byAddress.Clear();
            foreach (var fn in functions)
            {
                var row = new FunctionRow
                {
                    Address = fn.Address,
                    Module = map?.Resolve(fn.Address)?.Name ?? "",
                    Name = fn.Name ?? fn.DisplayName,
                    CallCount = fn.CallCount,
                };
                _rows.Add(row);
                _byAddress[fn.Address] = row;
            }
            _countMode = CountFilterMode.All; // a fresh dataset always starts fully visible
            SetLiveFiltering(false);          // snapshot default until "Hide 0-hit" is applied
            _firstCallOrderNext = 0;          // ranks restart with the new dataset
            _view.SortDescriptions.Clear();   // drop any call-order/column sort; show natural order
            _view.Refresh();
            UpdateMatchInfo();
        }

        /// <summary>
        /// Select the row for <paramref name="address"/> and scroll it into view
        /// (used when a node is clicked in the call-graph). Returns false if no
        /// such function is listed. The selection is applied silently — it does
        /// not raise <see cref="FunctionSelected"/> — so the caller can drive the
        /// rest of the UI itself without a double update.
        /// </summary>
        public bool SelectByAddress(ulong address)
        {
            if (!_byAddress.TryGetValue(address, out var row)) return false;
            _suppressSelectionEvent = true;
            try { Grid.SelectedItem = row; Grid.ScrollIntoView(row); }
            finally { _suppressSelectionEvent = false; }
            return true;
        }

        /// <summary>
        /// Tally a batch of captured calls onto the function rows: each record is
        /// an entry into its callee, so we count occurrences of each Destination.
        /// Batched per poll so a hot function updates its cell once, not per hit.
        /// </summary>
        public void AddCounts(IReadOnlyList<CallRecord> records)
        {
            if (records.Count == 0 || _byAddress.Count == 0) return;

            Dictionary<FunctionRow, long>? hits = null;
            foreach (var rec in records)
            {
                if (_byAddress.TryGetValue(rec.Destination, out var row))
                {
                    // Records arrive in call order, so the first time a function is seen
                    // is when it was first called: stamp its rank for the Order column.
                    if (row.FirstCallSeq == long.MaxValue) row.StampFirstCall(_firstCallOrderNext++);

                    hits ??= new Dictionary<FunctionRow, long>();
                    hits[row] = hits.TryGetValue(row, out long c) ? c + 1 : 1;
                }
            }
            if (hits == null) return;
            foreach (var kv in hits) kv.Key.AddCalls(kv.Value);

            // In the live "Hide 0-hit" view (e.g. after Clear calls), rows appear as
            // their counts cross zero; refresh the "showing X of Y" readout so it tracks
            // the functions revealed so far instead of going stale at the post-clear 0.
            // Gated to that mode so a normal capture keeps paying nothing per poll.
            if (_countMode == CountFilterMode.NonZero) UpdateMatchInfo();
        }

        /// <summary>
        /// Stamp each function's first-call rank from records given in call (time) order,
        /// without touching call counts — used when loading a saved trace whose counts are
        /// already populated, so "Call order" works offline too. Safe to call once after
        /// <see cref="LoadFromDataset"/>; re-stamping is idempotent per function.
        /// </summary>
        public void StampCallOrder(IReadOnlyList<CallRecord> recordsInOrder)
        {
            foreach (var rec in recordsInOrder)
                if (_byAddress.TryGetValue(rec.Destination, out var row) && row.FirstCallSeq == long.MaxValue)
                    row.StampFirstCall(_firstCallOrderNext++);
        }

        /// <summary>Zero every row's observed-call counter (a new capture starting).</summary>
        public void ResetCounts()
        {
            foreach (var r in _rows) { r.SetCalls(0); r.ResetFirstCall(); }
            _firstCallOrderNext = 0; // first-call ranks restart with the new capture
            // The counts just went to zero; a stale count filter (e.g. "Hide 0-hit")
            // would now hide almost everything, so fall back to showing all. (A caller
            // that wants only the post-reset calls re-applies HideZeroHit afterwards.)
            _countMode = CountFilterMode.All;
            SetLiveFiltering(false);
            _view.Refresh();
            UpdateMatchInfo();
        }

        /// <summary>
        /// Sort the list by the order functions were first called (rank ascending),
        /// with never-called functions falling to the bottom. A snapshot of the ranks
        /// known now — re-invoke to re-apply after more calls arrive. Click a column
        /// header to sort some other way.
        /// </summary>
        public void SortByCallOrder()
        {
            _view.SortDescriptions.Clear();
            _view.SortDescriptions.Add(new SortDescription(nameof(FunctionRow.FirstCallSeq), ListSortDirection.Ascending));
            _view.SortDescriptions.Add(new SortDescription(nameof(FunctionRow.Address), ListSortDirection.Ascending)); // stable tie-break
        }

        private void OnSortCallOrder(object sender, RoutedEventArgs e) => SortByCallOrder();

        private string _filter = "";

        private bool FilterRow(object o)
        {
            if (o is not FunctionRow r) return false;

            // Text filter (name / module / address).
            if (_filter.Length != 0)
            {
                bool textMatch =
                    r.Name.Contains(_filter, StringComparison.OrdinalIgnoreCase)
                    || r.Module.Contains(_filter, StringComparison.OrdinalIgnoreCase)
                    || r.AddressHex.Contains(_filter, StringComparison.OrdinalIgnoreCase);
                if (!textMatch) return false;
            }

            // Call-count filter (layered on top of the text filter).
            return _countMode switch
            {
                CountFilterMode.NonZero => r.CallCount > 0,
                CountFilterMode.Exact => r.CallCount == _countExact,
                _ => true,
            };
        }

        private void OnFilterChanged(object sender, TextChangedEventArgs e)
        {
            _filter = Filter.Text ?? "";
            _view.Refresh();
            UpdateMatchInfo();
        }

        // --- call-count filter (Hide 0-hit / Only N hits / Show all) ---------

        /// <summary>
        /// Hide functions with zero recorded calls (keep only those hit). Updates live:
        /// a function appears the moment its count crosses zero, so after a capture
        /// reset only the functions called since then are shown, filling in as they run.
        /// </summary>
        public void HideZeroHit()
        {
            _countMode = CountFilterMode.NonZero;
            SetLiveFiltering(true); // reveal newly-called functions as calls arrive
            ApplyCountFilter();
            CountFilterChanged?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>Show only functions whose call count equals <paramref name="n"/>.</summary>
        public void ShowOnlyCallCount(long n)
        {
            _countMode = CountFilterMode.Exact;
            _countExact = n;
            SetLiveFiltering(false); // a snapshot of the count when applied (no live flicker)
            ApplyCountFilter();
            CountFilterChanged?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>Clear the call-count filter — restore the full function list.</summary>
        public void ShowAllCounts()
        {
            _countMode = CountFilterMode.All;
            SetLiveFiltering(false);
            ApplyCountFilter();
            CountFilterChanged?.Invoke(this, EventArgs.Empty);
        }

        // Toggle live filtering on the view. On (only in "Hide 0-hit" mode) re-evaluates
        // a row's visibility whenever its CallCount changes, so newly-called functions
        // appear live during capture. Off restores snapshot behaviour for the other modes.
        private void SetLiveFiltering(bool on)
        {
            if (_view is ICollectionViewLiveShaping shaping && shaping.IsLiveFiltering != on)
                shaping.IsLiveFiltering = on;
        }

        private void OnHideZeroHit(object sender, RoutedEventArgs e) => HideZeroHit();

        private void OnShowAllCounts(object sender, RoutedEventArgs e) => ShowAllCounts();

        private void OnShowOnlyCount(object sender, RoutedEventArgs e) => ApplyExactFromBox();

        private void OnCountBoxKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) { ApplyExactFromBox(); e.Handled = true; }
        }

        // Parse the count box and apply an exact-count filter; ignore junk input.
        // Thousands separators are accepted so a value copied from the comma-grouped
        // "showing X of Y" readout parses too; parsing uses the current culture to
        // match how that readout is formatted (:N0).
        private void ApplyExactFromBox()
        {
            string text = (CountBox.Text ?? "").Trim();
            const NumberStyles styles = NumberStyles.Integer | NumberStyles.AllowThousands;
            if (!long.TryParse(text, styles, CultureInfo.CurrentCulture, out long n) || n < 0)
            {
                if (MatchInfo != null) MatchInfo.Text = "enter a whole number ≥ 0";
                return;
            }
            ShowOnlyCallCount(n);
        }

        private void ApplyCountFilter()
        {
            _view.Refresh();
            UpdateMatchInfo();
        }

        // "showing X of Y" readout. Counts the rows that pass the full predicate;
        // only runs on explicit filter actions and loads (never per captured call),
        // so the O(n) pass over the backing list is cheap.
        private void UpdateMatchInfo()
        {
            if (MatchInfo == null) return; // before the template is applied
            if (_countMode == CountFilterMode.All && _filter.Length == 0)
            {
                MatchInfo.Text = _rows.Count == 0 ? "" : $"{_rows.Count:N0} functions";
                return;
            }
            int shown = 0;
            foreach (var r in _rows) if (FilterRow(r)) shown++;
            MatchInfo.Text = $"showing {shown:N0} of {_rows.Count:N0}";
        }

        private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_suppressSelectionEvent) return;
            // Multi-select is for copying rows — don't focus/capture on it; only a
            // single selected row drives the rest of the UI (and a live trace).
            if (Grid.SelectedItems.Count > 1) return;
            if (Grid.SelectedItem is FunctionRow r)
                FunctionSelected?.Invoke(this, r.Address);
        }
    }
}
