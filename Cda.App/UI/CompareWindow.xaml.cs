using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using Cda.Core.Engine;

namespace Cda.App.UI
{
    /// <summary>
    /// Row view-model wrapping a <see cref="FunctionDiff"/> for the grid: the engine
    /// type stays WPF-free, this carries the display strings and the colour-keying
    /// tags the XAML binds to.
    /// </summary>
    public sealed class DiffRowVM
    {
        public DiffRowVM(FunctionDiff d) => Diff = d;

        public FunctionDiff Diff { get; }

        public string Label => Diff.Label;
        public string Module => Diff.Module;
        public ulong AddressA => Diff.AddressA;
        public ulong AddressB => Diff.AddressB;

        // Numeric values for column sorting (the *Text properties are display-only;
        // sorting on them would order lexically — "10" before "9").
        public long CountA => Diff.CountA;
        public long CountB => Diff.CountB;
        public long DeltaValue => Diff.Delta;

        public string CountAText => Diff.CountA.ToString("N0", CultureInfo.CurrentUICulture);
        public string CountBText => Diff.CountB.ToString("N0", CultureInfo.CurrentUICulture);

        public string DeltaText => Diff.Delta > 0
            ? "+" + Diff.Delta.ToString("N0", CultureInfo.CurrentUICulture)
            : Diff.Delta.ToString("N0", CultureInfo.CurrentUICulture);

        public string DeltaSign => Diff.Delta > 0 ? "pos" : Diff.Delta < 0 ? "neg" : "zero";

        public string StatusText => Diff.Status switch
        {
            TraceDiffStatus.OnlyA => "only A",
            TraceDiffStatus.OnlyB => "only B",
            TraceDiffStatus.Changed => "changed",
            _ => "same",
        };

        public string Kind => Diff.Status switch
        {
            TraceDiffStatus.OnlyA => "onlyA",
            TraceDiffStatus.OnlyB => "onlyB",
            TraceDiffStatus.Changed => "changed",
            _ => "same",
        };
    }

    /// <summary>Row view-model for the string-argument diff table.</summary>
    public sealed class StringRowVM
    {
        public StringRowVM(StringArgDiff d) => Diff = d;

        public StringArgDiff Diff { get; }

        public string Value => Diff.Value;
        public long CountA => Diff.CountA;        // numeric, for column sorting
        public long CountB => Diff.CountB;
        public long DeltaValue => Diff.Delta;

        public string CountAText => Diff.CountA.ToString("N0", CultureInfo.CurrentUICulture);
        public string CountBText => Diff.CountB.ToString("N0", CultureInfo.CurrentUICulture);

        public string DeltaText => Diff.Delta > 0
            ? "+" + Diff.Delta.ToString("N0", CultureInfo.CurrentUICulture)
            : Diff.Delta.ToString("N0", CultureInfo.CurrentUICulture);

        public string DeltaSign => Diff.Delta > 0 ? "pos" : Diff.Delta < 0 ? "neg" : "zero";

        public string StatusText => Diff.Status switch
        {
            TraceDiffStatus.OnlyA => "only A",
            TraceDiffStatus.OnlyB => "only B",
            TraceDiffStatus.Changed => "changed",
            _ => "same",
        };

        public string Kind => Diff.Status switch
        {
            TraceDiffStatus.OnlyA => "onlyA",
            TraceDiffStatus.OnlyB => "onlyB",
            TraceDiffStatus.Changed => "changed",
            _ => "same",
        };
    }

    /// <summary>
    /// Row view-model for the "passed to" sub-table: one callee that received the
    /// selected string argument, with its A vs B occurrence count.
    /// </summary>
    public sealed class StringSiteRowVM
    {
        public StringSiteRowVM(StringSiteDiff d) => Diff = d;

        public StringSiteDiff Diff { get; }

        public string Label => Diff.Label;
        public string Module => Diff.Module;
        public ulong AddressA => Diff.AddressA;

        public long CountA => Diff.CountA;        // numeric, for column sorting
        public long CountB => Diff.CountB;
        public long DeltaValue => Diff.Delta;

        public string CountAText => Diff.CountA.ToString("N0", CultureInfo.CurrentUICulture);
        public string CountBText => Diff.CountB.ToString("N0", CultureInfo.CurrentUICulture);

        public string DeltaText => Diff.Delta > 0
            ? "+" + Diff.Delta.ToString("N0", CultureInfo.CurrentUICulture)
            : Diff.Delta.ToString("N0", CultureInfo.CurrentUICulture);

        public string DeltaSign => Diff.Delta > 0 ? "pos" : Diff.Delta < 0 ? "neg" : "zero";

        public string StatusText => Diff.Status switch
        {
            TraceDiffStatus.OnlyA => "only A",
            TraceDiffStatus.OnlyB => "only B",
            TraceDiffStatus.Changed => "changed",
            _ => "same",
        };

        public string Kind => Diff.Status switch
        {
            TraceDiffStatus.OnlyA => "onlyA",
            TraceDiffStatus.OnlyB => "onlyB",
            TraceDiffStatus.Changed => "changed",
            _ => "same",
        };
    }

    /// <summary>
    /// Row view-model for a first-call-order context sub-table: one function as it sat
    /// in a single run's first-call sequence, near the selected function.
    /// </summary>
    public sealed class OrderContextRowVM
    {
        private readonly int _rank;

        public OrderContextRowVM(FunctionDiff d, int rank, bool isCenter)
        {
            Diff = d;
            _rank = rank;
            IsCenter = isCenter;
        }

        public FunctionDiff Diff { get; }

        /// <summary>True for the selected function itself (the centre of the window).</summary>
        public bool IsCenter { get; }

        public string RankText => _rank.ToString(CultureInfo.CurrentUICulture);
        public string Label => Diff.Label;
        public string Module => Diff.Module;
        public ulong AddressA => Diff.AddressA;
    }

    /// <summary>
    /// Row view-model for the first-call-order diff table: the rank at which each
    /// function was first called in A vs B, and how that rank moved.
    /// </summary>
    public sealed class FirstCallRowVM
    {
        public FirstCallRowVM(FunctionDiff d) => Diff = d;

        public FunctionDiff Diff { get; }

        public string Label => Diff.Label;
        public string Module => Diff.Module;
        public ulong AddressA => Diff.AddressA;

        public bool CalledA => Diff.RankA > 0;
        public bool CalledB => Diff.RankB > 0;

        /// <summary>Aligned by the sequence diff (kept its relative first-call order).</summary>
        public bool IsInOrder => Diff.SeqOrder == SeqOrderClass.InOrder;

        public string RankAText => CalledA ? Diff.RankA.ToString(CultureInfo.CurrentUICulture) : "—";
        public string RankBText => CalledB ? Diff.RankB.ToString(CultureInfo.CurrentUICulture) : "—";

        // Sort keys: a not-called rank sorts to the bottom of an ascending sort.
        public int RankASort => CalledA ? Diff.RankA : int.MaxValue;
        public int RankBSort => CalledB ? Diff.RankB : int.MaxValue;

        public string RankDeltaText => (CalledA && CalledB)
            ? (Diff.RankB - Diff.RankA).ToString("+0;-0;0", CultureInfo.CurrentUICulture)
            : "";
        public int RankDeltaSort => (CalledA && CalledB) ? Diff.RankB - Diff.RankA : 0;

        // Status from the LCS-aligned sequence diff, not a raw rank compare — so a
        // cascade (a rank that shifted only because a neighbour was added/removed) reads
        // "in order", and only a genuine reorder reads "moved".
        public string StatusText => Diff.SeqOrder switch
        {
            SeqOrderClass.InOrder => "in order",
            SeqOrderClass.Moved => "moved",
            SeqOrderClass.Removed => "only A",
            SeqOrderClass.Inserted => "only B",
            _ => "",
        };

        // Reuse the shared StatusCell colouring (keys on Kind); "moved" maps to the
        // "changed" (amber) colour, "in order" to the neutral "same".
        public string Kind => Diff.SeqOrder switch
        {
            SeqOrderClass.Moved => "changed",
            SeqOrderClass.Removed => "onlyA",
            SeqOrderClass.Inserted => "onlyB",
            _ => "same",
        };
    }

    /// <summary>
    /// Side-by-side comparison of two captured traces: a per-function call-count
    /// diff table on the left and the "where they differ" chart on the right.
    /// Double-clicking a row navigates the main window to that function (when it is
    /// present in the current trace, A).
    /// </summary>
    public partial class CompareWindow : Window
    {
        private const int ChartTopN = 30;

        private readonly TraceComparisonResult _result;
        private readonly Action<ulong>? _navigate;
        private readonly ObservableCollection<DiffRowVM> _rows = new();
        private readonly ICollectionView _view;

        private readonly ObservableCollection<StringRowVM> _strRows = new();
        private readonly ICollectionView _strView;

        // The "passed to" sub-table: the callees that received the selected string.
        private readonly ObservableCollection<StringSiteRowVM> _siteRows = new();

        private readonly ObservableCollection<FirstCallRowVM> _orderRows = new();
        private readonly ICollectionView _orderView;

        // First-call sequences indexed by 1-based rank (seq[rank-1] = that run's r-th
        // first-called function), and the side-by-side "context" sub-tables they feed.
        private FunctionDiff?[] _seqA = Array.Empty<FunctionDiff?>();
        private FunctionDiff?[] _seqB = Array.Empty<FunctionDiff?>();
        private readonly ObservableCollection<OrderContextRowVM> _ctxARows = new();
        private readonly ObservableCollection<OrderContextRowVM> _ctxBRows = new();
        private const int OrderContextRadius = 4;  // neighbours shown on each side

        private string _filter = "";
        private bool _changesOnly = true;
        private long _minDelta;       // hide rows whose |Δ| is below this (0 = no threshold)
        private double _minPct;       // hide rows whose relative change % is below this (0 = no threshold)

        private string _strFilter = "";
        private bool _strChangesOnly = true;

        private string _orderFilter = "";
        private bool _orderChangesOnly = true;

        public CompareWindow(TraceComparisonResult result, string labelA, string labelB, Action<ulong>? navigate)
        {
            InitializeComponent();
            _result = result;
            _navigate = navigate;

            foreach (var d in result.Functions) _rows.Add(new DiffRowVM(d));

            _view = CollectionViewSource.GetDefaultView(_rows);
            _view.Filter = FilterRow;
            Grid.ItemsSource = _view;

            foreach (var d in result.StringArgs) _strRows.Add(new StringRowVM(d));
            _strView = CollectionViewSource.GetDefaultView(_strRows);
            _strView.Filter = StrFilterRow;
            StrGrid.ItemsSource = _strView;
            SiteGrid.ItemsSource = _siteRows;

            BuildFirstCallSequences(result);

            foreach (var d in result.Functions) _orderRows.Add(new FirstCallRowVM(d));
            _orderView = CollectionViewSource.GetDefaultView(_orderRows);
            _orderView.Filter = OrderFilterRow;
            // Default to A's first-call sequence (not-called functions fall to the end).
            _orderView.SortDescriptions.Add(new SortDescription(nameof(FirstCallRowVM.RankASort), ListSortDirection.Ascending));
            _orderView.SortDescriptions.Add(new SortDescription(nameof(FirstCallRowVM.RankBSort), ListSortDirection.Ascending));
            OrderGrid.ItemsSource = _orderView;
            OrderCtxA.ItemsSource = _ctxARows;
            OrderCtxB.ItemsSource = _ctxBRows;

            Chart.BarSelected += OnChartBarSelected;

            HeaderText.Text = $"A: {labelA}      B: {labelB}";
            SummaryText.Text =
                $"{result.DifferingCount:N0} of {result.Functions.Count:N0} functions differ  ·  " +
                $"{result.OnlyACount:N0} only in A, {result.OnlyBCount:N0} only in B, {result.ChangedCount:N0} changed, {result.SameCount:N0} identical  ·  " +
                $"total calls: A {result.TotalCallsA:N0}  vs  B {result.TotalCallsB:N0}\n" +
                $"{result.EdgeDifferingCount:N0} caller→callee edges differ " +
                $"({result.EdgeOnlyACount:N0} only A, {result.EdgeOnlyBCount:N0} only B, {result.EdgeChangedCount:N0} changed)  ·  " +
                $"{result.StringDifferingCount:N0} string arguments differ ({result.StringOnlyACount:N0} only A, {result.StringOnlyBCount:N0} only B) — " +
                "select a function to colour the butterfly graph, or open the String arguments tab.";

            RefreshChart();
            UpdateMatchInfo();
            UpdateStrMatchInfo();
            UpdateOrderMatchInfo();
        }

        // "showing X of Y" readout, so the effect of the filter / "Differences only"
        // toggle is visible — e.g. that it hid nothing because the two runs share no
        // exactly-equal call counts.
        private void UpdateMatchInfo()
        {
            int shown = 0;
            foreach (var r in _rows) if (FilterRow(r)) shown++;
            MatchInfo.Text = $"showing {shown:N0} of {_rows.Count:N0} functions";
        }

        // --- string-argument tab --------------------------------------------

        private bool StrFilterRow(object o)
        {
            if (o is not StringRowVM r) return false;
            // "Differences only" keeps a row if its total count changed OR it changed where
            // it went (same total, but a receiving function's share moved between the runs).
            if (_strChangesOnly && r.Diff.Status == TraceDiffStatus.Same && !r.Diff.SitesChanged) return false;
            if (_strFilter.Length == 0) return true;
            return r.Value.Contains(_strFilter, StringComparison.OrdinalIgnoreCase);
        }

        private void OnStrFilterChanged(object sender, TextChangedEventArgs e)
        {
            _strFilter = StrFilter.Text ?? "";
            _strView.Refresh();
            UpdateStrMatchInfo();
        }

        private void OnStrChangesOnlyChanged(object sender, RoutedEventArgs e)
        {
            _strChangesOnly = StrChangesOnly.IsChecked == true;
            _strView.Refresh();
            UpdateStrMatchInfo();
        }

        private void UpdateStrMatchInfo()
        {
            int shown = 0;
            foreach (var r in _strRows) if (StrFilterRow(r)) shown++;
            StrMatchInfo.Text = _strRows.Count == 0
                ? "no string arguments recorded"
                : $"showing {shown:N0} of {_strRows.Count:N0} strings";
        }

        // Selecting a string fills the "passed to" sub-table with the functions that
        // received it (the where), so it's clear which call sites a string flowed into
        // and how that changed between the runs.
        private void OnStrSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _siteRows.Clear();
            if (StrGrid.SelectedItem is not StringRowVM r)
            {
                SiteHeader.Text = "PASSED TO — SELECT A STRING ABOVE";
                return;
            }
            foreach (var s in r.Diff.Sites) _siteRows.Add(new StringSiteRowVM(s));
            SiteHeader.Text = _siteRows.Count == 1
                ? "PASSED TO — 1 FUNCTION (double-click to centre the graph on it)"
                : $"PASSED TO — {_siteRows.Count:N0} FUNCTIONS (double-click one to centre the graph on it)";
        }

        // Double-clicking a string jumps to the function that received it most divergently
        // (its first site — sites are sorted by |Δ|), recolouring the butterfly graph there.
        private void OnStrRowDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (StrGrid.SelectedItem is not StringRowVM r) return;
            foreach (var s in r.Diff.Sites)
                if (s.AddressA != 0) { _navigate?.Invoke(s.AddressA); return; }
        }

        // Double-clicking a receiving function navigates the main window to it; while a
        // comparison is open that centres the diff butterfly graph on it, whose callers
        // are the functions that passed the string.
        private void OnSiteRowDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (SiteGrid.SelectedItem is StringSiteRowVM r && r.AddressA != 0) _navigate?.Invoke(r.AddressA);
        }

        // --- first-call-order tab -------------------------------------------

        private bool OrderFilterRow(object o)
        {
            if (o is not FirstCallRowVM r) return false;
            if (_orderChangesOnly && r.IsInOrder) return false; // hide the aligned (un-reordered) ones
            if (_orderFilter.Length == 0) return true;
            return r.Label.Contains(_orderFilter, StringComparison.OrdinalIgnoreCase)
                || r.Module.Contains(_orderFilter, StringComparison.OrdinalIgnoreCase);
        }

        private void OnOrderFilterChanged(object sender, TextChangedEventArgs e)
        {
            _orderFilter = OrderFilter.Text ?? "";
            _orderView.Refresh();
            UpdateOrderMatchInfo();
        }

        private void OnOrderChangesOnlyChanged(object sender, RoutedEventArgs e)
        {
            _orderChangesOnly = OrderChangesOnly.IsChecked == true;
            _orderView.Refresh();
            UpdateOrderMatchInfo();
        }

        private void UpdateOrderMatchInfo()
        {
            int shown = 0;
            foreach (var r in _orderRows) if (OrderFilterRow(r)) shown++;
            OrderMatchInfo.Text = $"showing {shown:N0} of {_orderRows.Count:N0} functions";
        }

        private void OnOrderRowDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (OrderGrid.SelectedItem is FirstCallRowVM r && r.AddressA != 0) _navigate?.Invoke(r.AddressA);
        }

        // Lay the functions out by 1-based first-call rank for each run. Ranks are unique
        // and contiguous (1..N) within a run, so every slot is filled.
        private void BuildFirstCallSequences(TraceComparisonResult result)
        {
            int maxA = 0, maxB = 0;
            foreach (var d in result.Functions)
            {
                if (d.RankA > maxA) maxA = d.RankA;
                if (d.RankB > maxB) maxB = d.RankB;
            }
            _seqA = new FunctionDiff?[maxA];
            _seqB = new FunctionDiff?[maxB];
            foreach (var d in result.Functions)
            {
                if (d.RankA > 0) _seqA[d.RankA - 1] = d;
                if (d.RankB > 0) _seqB[d.RankB - 1] = d;
            }
        }

        // Selecting a function fills the two context tables with what each run called
        // around it in first-call order — the "where" of a reorder. Empty on the side
        // where the function wasn't called.
        private void OnOrderSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ctxARows.Clear();
            _ctxBRows.Clear();
            if (OrderGrid.SelectedItem is not FirstCallRowVM r)
            {
                OrderCtxHeader.Text = "FIRST-CALL CONTEXT — SELECT A FUNCTION ABOVE";
                OrderCtxAHeader.Text = "AROUND IT IN A";
                OrderCtxBHeader.Text = "AROUND IT IN B";
                return;
            }

            FillContext(_ctxARows, _seqA, r.Diff.RankA);
            FillContext(_ctxBRows, _seqB, r.Diff.RankB);
            OrderCtxHeader.Text = $"FIRST-CALL CONTEXT FOR {r.Label} — what each run called around it (double-click a function to centre the graph on it)";
            OrderCtxAHeader.Text = r.Diff.RankA > 0 ? $"AROUND IT IN A (rank {r.Diff.RankA})" : "NOT CALLED IN A";
            OrderCtxBHeader.Text = r.Diff.RankB > 0 ? $"AROUND IT IN B (rank {r.Diff.RankB})" : "NOT CALLED IN B";
        }

        private static void FillContext(ObservableCollection<OrderContextRowVM> rows, FunctionDiff?[] seq, int rank)
        {
            if (rank <= 0) return; // not called in this run — leave the side empty
            int center = rank - 1;
            int lo = Math.Max(0, center - OrderContextRadius);
            int hi = Math.Min(seq.Length - 1, center + OrderContextRadius);
            for (int i = lo; i <= hi; i++)
            {
                var d = seq[i];
                if (d != null) rows.Add(new OrderContextRowVM(d, i + 1, i == center));
            }
        }

        private void OnOrderCtxADoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (OrderCtxA.SelectedItem is OrderContextRowVM r && r.AddressA != 0) _navigate?.Invoke(r.AddressA);
        }

        private void OnOrderCtxBDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (OrderCtxB.SelectedItem is OrderContextRowVM r && r.AddressA != 0) _navigate?.Invoke(r.AddressA);
        }

        private bool FilterRow(object o)
        {
            if (o is not DiffRowVM r) return false;
            if (_changesOnly && r.Diff.Status == TraceDiffStatus.Same) return false;
            if (r.Diff.AbsDelta < _minDelta) return false; // below the Min Δ threshold
            if (_minPct > 0 && PercentChange(r.Diff) < _minPct) return false; // below the Min % threshold
            if (_filter.Length == 0) return true;
            return r.Label.Contains(_filter, StringComparison.OrdinalIgnoreCase)
                || r.Module.Contains(_filter, StringComparison.OrdinalIgnoreCase);
        }

        private void OnFilterChanged(object sender, TextChangedEventArgs e)
        {
            _filter = Filter.Text ?? "";
            _view.Refresh();
            RefreshChart();
            UpdateMatchInfo();
        }

        private void OnChangesOnlyChanged(object sender, RoutedEventArgs e)
        {
            _changesOnly = ChangesOnly.IsChecked == true;
            _view.Refresh();
            RefreshChart();
            UpdateMatchInfo();
        }

        private void OnMinDeltaChanged(object sender, TextChangedEventArgs e)
        {
            // Blank or non-numeric (or negative) means "no threshold" — show everything.
            string t = (MinDeltaBox.Text ?? "").Trim();
            if (t.Length == 0 ||
                !long.TryParse(t, NumberStyles.Integer | NumberStyles.AllowThousands, CultureInfo.CurrentCulture, out long n) ||
                n < 0)
                n = 0;
            _minDelta = n;
            _view.Refresh();
            RefreshChart();
            UpdateMatchInfo();
        }

        private void OnMinPctChanged(object sender, TextChangedEventArgs e)
        {
            // Tolerant of a trailing '%'; blank/junk/negative means "no threshold".
            string t = (MinPctBox.Text ?? "").Trim().TrimEnd('%', ' ');
            if (t.Length == 0 ||
                !double.TryParse(t, NumberStyles.Float | NumberStyles.AllowThousands, CultureInfo.CurrentCulture, out double p) ||
                p < 0)
                p = 0;
            _minPct = p;
            _view.Refresh();
            RefreshChart();
            UpdateMatchInfo();
        }

        // Relative change of an edge/function's call count: |Δ| as a percent of the
        // larger side, so a new/removed function (one side 0) is 100% and a small drift
        // on a hot function is near 0%. Denominator is floored at 1 (a row only exists
        // when called at least once, so this is just defensive).
        private static double PercentChange(FunctionDiff d)
        {
            long denom = Math.Max(1, Math.Max(d.CountA, d.CountB));
            return (double)d.AbsDelta / denom * 100.0;
        }

        // The chart shows the top-N differing rows that pass the current filter,
        // in the engine's |delta|-descending order (the source order of _rows).
        private void RefreshChart()
        {
            var top = new List<FunctionDiff>(ChartTopN);
            foreach (var r in _rows)
            {
                if (r.Diff.Delta == 0) continue;          // a delta of 0 has nothing to chart
                if (!FilterRow(r)) continue;
                top.Add(r.Diff);
                if (top.Count >= ChartTopN) break;
            }
            Chart.SetItems(top);
        }

        private void OnChartBarSelected(object? sender, FunctionDiff d)
        {
            // Find the row for this diff and select + scroll to it.
            foreach (var r in _rows)
                if (ReferenceEquals(r.Diff, d))
                {
                    Grid.SelectedItem = r;
                    Grid.ScrollIntoView(r);
                    break;
                }
        }

        private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Selection alone doesn't navigate (double-click does), so a click in the
            // table doesn't yank the main window around; nothing to do here yet.
        }

        private void OnRowDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (Grid.SelectedItem is not DiffRowVM r) return;
            if (r.AddressA != 0) _navigate?.Invoke(r.AddressA);
            // If it's only in B there's no address in the current (A) views to select.
        }

        private void OnCopy(object sender, RoutedEventArgs e)
        {
            try
            {
                Clipboard.SetText(BuildReport());
                Title = "Compare traces — copied report to clipboard";
            }
            catch { /* clipboard contention; ignore */ }
        }

        private void OnClose(object sender, RoutedEventArgs e) => Close();

        private static string SiteStatus(TraceDiffStatus s) => s switch
        {
            TraceDiffStatus.OnlyA => "only A",
            TraceDiffStatus.OnlyB => "only B",
            TraceDiffStatus.Changed => "changed",
            _ => "same",
        };

        private string BuildReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("CDA — trace comparison");
            sb.AppendLine(HeaderText.Text);
            sb.AppendLine(SummaryText.Text);
            sb.AppendLine();
            sb.AppendLine($"  {"status",-8}  {"callsA",8}  {"callsB",8}  {"delta",8}  function");
            foreach (var r in _rows)
            {
                if (!FilterRow(r)) continue;
                sb.AppendLine($"  {r.StatusText,-8}  {r.Diff.CountA,8:N0}  {r.Diff.CountB,8:N0}  {r.DeltaText,8}  {r.Label}"
                              + (string.IsNullOrEmpty(r.Module) ? "" : $"  [{r.Module}]"));
            }

            // String arguments (honouring that tab's filter), each followed by the
            // functions that received it (the "where"), indented.
            sb.AppendLine();
            sb.AppendLine("# string arguments");
            sb.AppendLine($"  {"status",-8}  {"seenA",8}  {"seenB",8}  {"delta",8}  value");
            foreach (var r in _strRows)
            {
                if (!StrFilterRow(r)) continue;
                sb.AppendLine($"  {r.StatusText,-8}  {r.Diff.CountA,8:N0}  {r.Diff.CountB,8:N0}  {r.DeltaText,8}  \"{r.Value}\"");
                foreach (var s in r.Diff.Sites)
                {
                    string delta = s.Delta > 0 ? "+" + s.Delta.ToString("N0") : s.Delta.ToString("N0");
                    sb.AppendLine($"      {"→ " + SiteStatus(s.Status),-10}{s.CountA,8:N0}  {s.CountB,8:N0}  {delta,8}  {s.Label}"
                                  + (string.IsNullOrEmpty(s.Module) ? "" : $"  [{s.Module}]"));
                }
            }

            // First-call order (honouring that tab's filter; in display order).
            sb.AppendLine();
            sb.AppendLine("# first-call order");
            sb.AppendLine($"  {"status",-8}  {"rankA",6}  {"rankB",6}  {"Δrank",6}  function");
            foreach (FirstCallRowVM r in _orderView)
            {
                if (!OrderFilterRow(r)) continue;
                sb.AppendLine($"  {r.StatusText,-8}  {r.RankAText,6}  {r.RankBText,6}  {r.RankDeltaText,6}  {r.Label}"
                              + (string.IsNullOrEmpty(r.Module) ? "" : $"  [{r.Module}]"));
            }
            return sb.ToString();
        }
    }
}
