using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using Cda.Core.Engine;

namespace Cda.App.UI
{
    /// <summary>
    /// "Strings" panel: every printable string mined from the launched/opened
    /// module, searchable, with the functions that reference each one. Picking a
    /// string (or one of its referencing functions) raises
    /// <see cref="FunctionActivated"/> so the host can jump the rest of the UI —
    /// the function list, call graph, hex view, and any live trace — to that code.
    /// This is the analogue of the Strings + cross-reference window in IDA/Ghidra.
    /// </summary>
    public partial class StringsView : UserControl
    {
        /// <summary>A function that references the selected string.</summary>
        public sealed class RefRow
        {
            public ulong Address { get; init; }
            public string AddressHex => "0x" + Address.ToString("X");
            public string Module { get; init; } = "";
            public string Name { get; init; } = "";
        }

        /// <summary>Row view-model for the strings grid.</summary>
        public sealed class StringRow
        {
            public ulong Address { get; init; }
            public string AddressHex => "0x" + Address.ToString("X");
            public string KindGlyph { get; init; } = "A";   // A = ASCII, W = wide (UTF-16)
            public string Text { get; init; } = "";          // the full string
            public string Display { get; init; } = "";       // single-line preview for the cell
            public int RefCount { get; init; }
            public ulong PrimaryFunctionAddr { get; init; }
            public string PrimaryFunction { get; init; } = "";
            public IReadOnlyList<RefRow> Refs { get; init; } = Array.Empty<RefRow>();
            public bool HasRefs => Refs.Count > 0;
        }

        // The backing rows are a plain list assigned in one shot (see SetRows); only
        // the small "referenced by" detail list is observable.
        private List<StringRow> _allRows = new();
        private readonly ObservableCollection<RefRow> _detail = new();
        private ICollectionView? _view;
        private bool _suppressDetailEvent;

        /// <summary>Raised with the entry address of a function the user chose to jump to.</summary>
        public event EventHandler<ulong>? FunctionActivated;

        /// <summary>Raised when the panel becomes visible (the Strings tab was opened).</summary>
        public event EventHandler? Shown;

        public StringsView()
        {
            InitializeComponent();
            DetailGrid.ItemsSource = _detail;
            RebuildView();
            GridCopy.Enable(Grid);
            GridCopy.Enable(DetailGrid);
            IsVisibleChanged += (_, e) => { if (e.NewValue is true) Shown?.Invoke(this, EventArgs.Empty); };
        }

        /// <summary>
        /// Build the display rows from the raw strings — pure data, safe to call on a
        /// worker thread (resolving each referencing function entry to a name/module),
        /// so the heavy part never runs on the UI thread.
        /// </summary>
        public static List<StringRow> BuildRows(
            IReadOnlyList<ExtractedString> strings, Func<ulong, (string Name, string Module)> resolve)
        {
            var rows = new List<StringRow>(strings.Count);
            foreach (var s in strings)
            {
                IReadOnlyList<RefRow> refs = Array.Empty<RefRow>();
                if (s.ReferencedBy.Count > 0)
                {
                    var list = new List<RefRow>(s.ReferencedBy.Count);
                    foreach (var fnAddr in s.ReferencedBy)
                    {
                        var (name, module) = resolve(fnAddr);
                        list.Add(new RefRow { Address = fnAddr, Name = name, Module = module });
                    }
                    refs = list;
                }

                rows.Add(new StringRow
                {
                    Address = s.Address,
                    KindGlyph = s.Kind == StringKind.Utf16 ? "W" : "A",
                    Text = s.Text,
                    Display = OneLine(s.Text),
                    RefCount = s.RefSites,
                    PrimaryFunctionAddr = refs.Count > 0 ? refs[0].Address : 0,
                    PrimaryFunction = refs.Count > 0
                        ? (refs.Count > 1 ? $"{refs[0].Name}  (+{refs.Count - 1})" : refs[0].Name)
                        : "",
                    Refs = refs,
                });
            }
            return rows;
        }

        /// <summary>Assign pre-built rows in a single operation (UI thread) — no
        /// per-item notifications, so even a very large list populates without freezing.</summary>
        public void SetRows(List<StringRow> rows)
        {
            _allRows = rows;
            _detail.Clear();
            SelectedString.Text = "";
            RebuildView();
            DetailHeader.Text = "Referenced by — select a string above.";
            UpdateMatchInfo();
        }

        /// <summary>Empty the panel (no static image backing the current view). Also
        /// resets the search so a stale filter can't silently hide a new target's
        /// strings (which would read as "strings missing").</summary>
        public void Clear()
        {
            _filter = "";
            if (Filter != null && Filter.Text.Length != 0) Filter.Text = ""; // fires OnFilterChanged
            SetRows(new List<StringRow>());
        }

        /// <summary>Show a transient status line (e.g. while a deferred scan runs).</summary>
        public void SetStatus(string text)
        {
            if (MatchInfo != null) MatchInfo.Text = text;
        }

        private void RebuildView()
        {
            _view = CollectionViewSource.GetDefaultView(_allRows);
            Grid.ItemsSource = _view;
            ApplyFilter();
        }

        // --- filtering -------------------------------------------------------

        private string _filter = "";
        private Predicate<object>? _filterPredicate;

        private bool FilterRow(object o)
        {
            if (o is not StringRow r) return false;
            if (OnlyReferenced.IsChecked == true && !r.HasRefs) return false;
            if (_filter.Length != 0 &&
                !r.Text.Contains(_filter, StringComparison.OrdinalIgnoreCase))
                return false;
            return true;
        }

        // Only attach the (O(n)) filter when a search or the "Only referenced" toggle
        // is actually active; with neither, the view is an unfiltered pass-through, so
        // loading a huge list costs nothing on the UI thread.
        private void ApplyFilter()
        {
            if (_view == null) return;
            _filterPredicate ??= FilterRow;
            bool active = _filter.Length != 0 || OnlyReferenced.IsChecked == true;
            Predicate<object>? desired = active ? _filterPredicate : null;
            if (!ReferenceEquals(_view.Filter, desired)) _view.Filter = desired; // change auto-refreshes
            else if (active) _view.Refresh(); // same predicate, but the search text changed
        }

        private void OnFilterChanged(object sender, TextChangedEventArgs e)
        {
            _filter = Filter.Text ?? "";
            ApplyFilter();
            UpdateMatchInfo();
        }

        private void OnOnlyReferencedChanged(object sender, RoutedEventArgs e)
        {
            ApplyFilter();
            UpdateMatchInfo();
        }

        private void UpdateMatchInfo()
        {
            if (MatchInfo == null) return;
            int total = _allRows.Count;
            if (total == 0) { MatchInfo.Text = ""; return; }
            // Common case (just loaded, no filter): no O(n) pass needed.
            if (_filter.Length == 0 && OnlyReferenced.IsChecked != true)
            {
                MatchInfo.Text = $"{total:N0} strings";
                return;
            }
            int shown = 0;
            foreach (var r in _allRows) if (FilterRow(r)) shown++;
            MatchInfo.Text = $"showing {shown:N0} of {total:N0}";
        }

        // --- selection / activation ------------------------------------------

        private void OnStringSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _suppressDetailEvent = true;
            _detail.Clear();
            try
            {
                if (Grid.SelectedItem is not StringRow r)
                {
                    SelectedString.Text = "";
                    DetailHeader.Text = "Referenced by — select a string above.";
                    return;
                }
                // The full value — wraps and scrolls. Bounded only to keep a pathological
                // multi-megabyte "string" (a data blob) from freezing the TextBox layout;
                // no real string approaches this, so it's effectively "the whole string".
                const int boxMax = 262144;
                SelectedString.Text = r.Text.Length <= boxMax
                    ? r.Text
                    : r.Text.Substring(0, boxMax) + $"\n…(showing first {boxMax:N0} of {r.Text.Length:N0} chars)";
                foreach (var rf in r.Refs) _detail.Add(rf);
                DetailHeader.Text = r.Refs.Count == 0
                    ? $"{r.Text.Length:N0} chars · no code reference found (loaded by API or data-only)."
                    : $"{r.Text.Length:N0} chars · referenced by {r.Refs.Count} function(s):";
            }
            finally { _suppressDetailEvent = false; }
        }

        private void OnStringDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (Grid.SelectedItem is StringRow r && r.PrimaryFunctionAddr != 0)
                FunctionActivated?.Invoke(this, r.PrimaryFunctionAddr);
        }

        private void OnDetailSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_suppressDetailEvent) return;
            if (DetailGrid.SelectedItems.Count > 1) return; // multi-select is for copy, not navigation
            if (DetailGrid.SelectedItem is RefRow r && r.Address != 0)
                FunctionActivated?.Invoke(this, r.Address);
        }

        // A bounded single-line preview for the grid cell and hover tooltip — the cell
        // trims it to the column width anyway, and a multi-megabyte string shouldn't
        // be laid out per cell. The complete value (any length) is shown in the detail
        // box when the row is selected.
        private static string OneLine(string s) =>
            s.Length <= 1000 ? s : s.Substring(0, 1000) + "…";
    }
}
