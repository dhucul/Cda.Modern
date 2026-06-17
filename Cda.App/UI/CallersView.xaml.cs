using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace Cda.App.UI
{
    /// <summary>
    /// "Called by" panel: a recursive caller tree (feature "B"). The top level is
    /// the selected function's direct callers; expanding a caller shows ITS
    /// callers, and so on — composed across all captured calls so the chain
    /// reaches further back than any single stack snapshot, back toward the
    /// program's entry point. Depth-capped and cycle-guarded host-side. Clicking a
    /// node navigates to that function.
    /// </summary>
    public partial class CallersView : UserControl
    {
        public sealed class CallerNode
        {
            /// <summary>Entry address of the calling function (or raw site if unknown).</summary>
            public ulong Address { get; init; }
            public string Caller { get; init; } = "";
            public string Module { get; init; } = "";
            public long Count { get; init; }
            public bool IsRecursion { get; init; }
            public ObservableCollection<CallerNode> Children { get; } = new();

            public string ModuleSuffix => string.IsNullOrEmpty(Module) ? "" : "   (" + Module + ")";
            public string CountSuffix => IsRecursion ? "   \u21BB recursion"
                                       : (Count > 0 ? "   \u00d7" + Count : "");
        }

        private readonly ObservableCollection<CallerNode> _roots = new();

        /// <summary>Raised when a caller node is clicked, with its resolved address.</summary>
        public event EventHandler<ulong>? CallerSelected;

        public CallersView()
        {
            InitializeComponent();
            Tree.ItemsSource = _roots;
            Tree.SelectedItemChanged += OnSelectedItemChanged;

            // Copy support: the selected caller line, or the whole subtree (indented).
            var copy = new MenuItem { Header = "Copy", InputGestureText = "Ctrl+C" };
            copy.Click += (_, _) => CopyNode(subtree: false);
            var copySub = new MenuItem { Header = "Copy subtree" };
            copySub.Click += (_, _) => CopyNode(subtree: true);
            Tree.ContextMenu = new ContextMenu();
            Tree.ContextMenu.Items.Add(copy);
            Tree.ContextMenu.Items.Add(copySub);

            // Right-click selects the node under the cursor so Copy acts on it.
            Tree.PreviewMouseRightButtonDown += (_, e) =>
            {
                for (DependencyObject? d = e.OriginalSource as DependencyObject; d != null; d = VisualTreeHelper.GetParent(d))
                    if (d is TreeViewItem item) { item.IsSelected = true; break; }
            };
            Tree.PreviewKeyDown += (_, e) =>
            {
                if (e.Key == Key.C && (Keyboard.Modifiers & ModifierKeys.Control) != 0)
                {
                    CopyNode(subtree: false);
                    e.Handled = true;
                }
            };
        }

        private void CopyNode(bool subtree)
        {
            if (Tree.SelectedItem is not CallerNode n) return;
            var sb = new StringBuilder();
            AppendNode(sb, n, 0, subtree);
            try { Clipboard.SetText(sb.ToString()); } catch { /* clipboard busy */ }
        }

        private static void AppendNode(StringBuilder sb, CallerNode n, int depth, bool recurse)
        {
            sb.Append(' ', depth * 2).Append(n.Caller).Append(n.ModuleSuffix).Append(n.CountSuffix).Append('\n');
            if (recurse)
                foreach (var c in n.Children) AppendNode(sb, c, depth + 1, true);
        }

        public void Clear()
        {
            _roots.Clear();
            Header.Text = "Select a function to see who calls it.";
        }

        /// <summary>Render the caller tree (roots = direct callers of <paramref name="title"/>).</summary>
        public void Show(string title, long totalCalls, IReadOnlyList<CallerNode> roots)
        {
            _roots.Clear();
            foreach (var r in roots) _roots.Add(r);
            UpdateHeader(title, totalCalls, roots.Count);
        }

        /// <summary>Update just the header counts (used live, without rebuilding the tree).</summary>
        public void UpdateHeader(string title, long totalCalls, int directCallers)
        {
            Header.Text = directCallers == 0
                ? $"No local callers of {title} recorded yet \u2014 exercise the program."
                : $"{title} \u2014 {totalCalls} call(s) \u00b7 {directCallers} direct caller(s) \u00b7 expand to trace back";
        }

        private void OnSelectedItemChanged(object? sender, RoutedPropertyChangedEventArgs<object> e)
        {
            if (e.NewValue is CallerNode n && n.Address != 0 && !n.IsRecursion)
                CallerSelected?.Invoke(this, n.Address);
        }
    }
}
