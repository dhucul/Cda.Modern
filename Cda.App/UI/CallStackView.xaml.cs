using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Windows.Controls;

namespace Cda.App.UI
{
    /// <summary>
    /// "Call stack" panel: for one captured call, the chain of the program's own
    /// frames that led to it, reconstructed from the stack snapshot the capture
    /// stub recorded. Frame 0 is the call site nearest the callee; deeper rows go
    /// outward toward the program's entry point. Runtime/CRT wrapper frames in
    /// system DLLs are skipped, so the chain reads back into the local program
    /// (e.g. CreateFileW ← App!LoadConfig ← App!Startup). Clicking a frame
    /// navigates to it. Depth is bounded by the captured snapshot.
    /// </summary>
    public partial class CallStackView : UserControl
    {
        public sealed class Frame
        {
            /// <summary>Entry address of the calling function (or the raw return site).</summary>
            public ulong Address { get; init; }
            public string Depth { get; init; } = "";
            public string Function { get; init; } = "";
            public string Module { get; init; } = "";
        }

        private readonly ObservableCollection<Frame> _rows = new();

        /// <summary>Raised when a frame row is clicked, with its resolved address.</summary>
        public event EventHandler<ulong>? FrameSelected;

        public CallStackView()
        {
            InitializeComponent();
            Grid.ItemsSource = _rows;
            Grid.SelectionChanged += OnSelectionChanged;
            GridCopy.Enable(Grid);
        }

        public void Clear()
        {
            _rows.Clear();
            Header.Text = "Click a call in the Calls tab to trace it back into the program.";
        }

        /// <summary>Render the local call chain for one call.</summary>
        public void Show(string title, IReadOnlyList<Frame> frames)
        {
            _rows.Clear();
            foreach (var f in frames) _rows.Add(f);
            Header.Text = frames.Count == 0
                ? $"{title} — no local frames captured (no snapshot, or the call came from outside the program)."
                : $"{title} — back through {frames.Count} local frame(s):";
        }

        private void OnSelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (Grid.SelectedItems.Count > 1) return; // multi-select is for copy, not navigation
            if (Grid.SelectedItem is Frame r && r.Address != 0)
                FrameSelected?.Invoke(this, r.Address);
        }
    }
}
