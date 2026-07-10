using System;
using System.Collections.ObjectModel;
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
        public sealed class Row
        {
            public string Time { get; init; } = "";
            public string Api { get; init; } = "";
            public string Caption { get; init; } = "";
            public string Caller { get; init; } = "";
            public string Module { get; init; } = "";
            public string Branch { get; init; } = "";

            /// <summary>Entry address of the app function that raised the dialog (0 if unknown).</summary>
            public ulong Address { get; init; }
            /// <summary>Address of the conditional branch that gates the dialog call (0 if not resolved).</summary>
            public ulong BranchAddress { get; init; }
            /// <summary>The dialog call itself, so a click can re-show its exact call stack.</summary>
            public CallRecord? Record { get; init; }
        }

        private readonly ObservableCollection<Row> _rows = new();

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
            Header.Text = "Dialog boxes the target raises will appear here, each with the app function that " +
                          "created it. Start 'Detect dialog caller' or 'Launch & detect dialogs…'.";
        }

        /// <summary>Append one captured dialog and update the header count.</summary>
        public void Add(Row row)
        {
            _rows.Add(row);
            Header.Text = $"{_rows.Count} dialog(s) captured — click one to see the function that raised it.";
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
