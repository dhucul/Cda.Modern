using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Controls;
using Cda.Core.Model;

namespace Cda.App.UI
{
    /// <summary>
    /// "Dialogs" panel: one row per dialog box the target raised while a
    /// dialog-caller capture is running, showing when it appeared, which OS
    /// function created it (MessageBox / DialogBoxParam / TaskDialog / …), its
    /// caption or text where available, and — the point of the feature — the app
    /// function that raised it, attributed from the captured stack snapshot.
    /// Clicking a row navigates to that caller (function list, graph, hex,
    /// disassembly) and re-shows its full call stack.
    /// </summary>
    public partial class DialogListView : UserControl
    {
        public sealed class Row : INotifyPropertyChanged
        {
            public string Time { get; init; } = "";
            public string Api { get; init; } = "";
            public string Caption { get; init; } = "";
            public string Caller { get; init; } = "";
            public string Module { get; init; } = "";

            // Branch + BranchAddress are mutable/notifying: the row is first added with the
            // STATIC guess, then upgraded in place to the hardware-CONFIRMED gate when the
            // branch probe reports it (see UpgradeBranch). The grid binds {Binding Branch}
            // OneWay, so PropertyChanged refreshes the cell.
            private string _branch = "";
            public string Branch
            {
                get => _branch;
                set { if (_branch != value) { _branch = value; OnChanged(nameof(Branch)); } }
            }

            /// <summary>Entry address of the app function that raised the dialog (0 if unknown).</summary>
            public ulong Address { get; init; }

            /// <summary>Address of the conditional branch that gates the dialog call (0 if not resolved).</summary>
            private ulong _branchAddress;
            public ulong BranchAddress
            {
                get => _branchAddress;
                set { if (_branchAddress != value) { _branchAddress = value; OnChanged(nameof(BranchAddress)); } }
            }

            /// <summary>Correlates a runtime-confirmed branch back to this row (0 = no probe).</summary>
            public ulong CallSiteKey { get; init; }

            /// <summary>True once the gate was confirmed from hardware (not just the static guess).</summary>
            private bool _confirmed;
            public bool Confirmed
            {
                get => _confirmed;
                set { if (_confirmed != value) { _confirmed = value; OnChanged(nameof(Confirmed)); } }
            }

            /// <summary>The dialog call itself, so a click can re-show its exact call stack.</summary>
            public CallRecord? Record { get; init; }

            public event PropertyChangedEventHandler? PropertyChanged;
            private void OnChanged(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        private readonly ObservableCollection<Row> _rows = new();

        // Rows indexed by call site, so a confirmed branch can upgrade every row that came
        // from the same gating code path.
        private readonly Dictionary<ulong, List<Row>> _byCallSite = new();

        /// <summary>Raised when a dialog row is clicked, with the caller's resolved address.</summary>
        public event EventHandler<ulong>? CallerSelected;

        /// <summary>Raised when a dialog row is clicked, with the dialog call record.</summary>
        public event EventHandler<CallRecord>? RowActivated;

        public DialogListView()
        {
            InitializeComponent();
            Grid.ItemsSource = _rows;
            Grid.SelectionChanged += OnSelectionChanged;
            GridCopy.Enable(Grid);
        }

        public int Count => _rows.Count;

        public void Clear()
        {
            _rows.Clear();
            _byCallSite.Clear();
            Header.Text = "Dialog boxes the target raises will appear here, each with the app function that " +
                          "created it. Start 'Detect dialog caller' or 'Launch & detect dialogs…'.";
        }

        /// <summary>Append one captured dialog and update the header count.</summary>
        public void Add(Row row)
        {
            _rows.Add(row);
            if (row.CallSiteKey != 0)
            {
                if (!_byCallSite.TryGetValue(row.CallSiteKey, out var list))
                    _byCallSite[row.CallSiteKey] = list = new List<Row>();
                list.Add(row);
            }
            Header.Text = $"{_rows.Count} dialog(s) captured — click one to see the function that raised it.";
        }

        /// <summary>
        /// Upgrade every row for <paramref name="callSiteKey"/> from the static branch guess
        /// to the hardware-confirmed gate (with its real direction). Idempotent; UI thread.
        /// </summary>
        public void UpgradeBranch(ulong callSiteKey, string branchText, ulong branchAddr)
        {
            if (callSiteKey == 0 || !_byCallSite.TryGetValue(callSiteKey, out var rows)) return;
            foreach (var r in rows)
            {
                r.Branch = branchText;
                r.BranchAddress = branchAddr;
                r.Confirmed = true;
            }
        }

        private void OnSelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (Grid.SelectedItems.Count > 1) return; // multi-select is for copy, not navigation
            if (Grid.SelectedItem is Row r)
            {
                if (r.Record != null) RowActivated?.Invoke(this, r.Record);
                if (r.Address != 0) CallerSelected?.Invoke(this, r.Address);
            }
        }
    }
}
