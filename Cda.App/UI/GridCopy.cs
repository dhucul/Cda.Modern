using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace Cda.App.UI
{
    /// <summary>
    /// Adds "select lines and copy them" to a read-only <see cref="DataGrid"/>:
    /// multi-row (Extended) selection, header-inclusive clipboard text, a right-click
    /// <b>Copy</b> / <b>Select all</b> menu, and right-click selects the row under the
    /// cursor so Copy acts on it. Ctrl+C and Ctrl+A keep working through the grid's
    /// built-in commands; the menu makes it discoverable and works regardless of which
    /// element currently has keyboard focus.
    /// </summary>
    public static class GridCopy
    {
        /// <param name="selectRowOnRightClick">When true, a right-click selects the row
        /// under the cursor so Copy acts on it. Pass false for a grid where selecting a
        /// row has side effects (e.g. the function list, where it refocuses a live trace);
        /// there, Copy acts on whatever is already selected.</param>
        public static void Enable(DataGrid grid, bool selectRowOnRightClick = true)
        {
            grid.SelectionMode = DataGridSelectionMode.Extended;
            grid.ClipboardCopyMode = DataGridClipboardCopyMode.IncludeHeader;

            var copy = new MenuItem { Header = "Copy", InputGestureText = "Ctrl+C" };
            copy.Click += (_, _) => DoCopy(grid);
            var selectAll = new MenuItem { Header = "Select all", InputGestureText = "Ctrl+A" };
            selectAll.Click += (_, _) => grid.SelectAll();
            var menu = new ContextMenu();
            menu.Items.Add(copy);
            menu.Items.Add(selectAll);
            grid.ContextMenu = menu;

            if (!selectRowOnRightClick) return;

            // Right-click selects the row under the cursor (unless it's already part of
            // the selection) so the menu's Copy has something to act on.
            grid.PreviewMouseRightButtonDown += (_, e) =>
            {
                var row = FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
                if (row != null && !row.IsSelected)
                {
                    grid.SelectedItems.Clear();
                    row.IsSelected = true;
                }
            };
        }

        // Copy the selected rows as tab-separated text via the grid's built-in Copy
        // command (which formats each visible column). Acts only on the current
        // selection — "Select all" is the explicit way to grab everything, so a stray
        // Copy can't dump a 200k-row grid to the clipboard.
        private static void DoCopy(DataGrid grid)
        {
            if (grid.SelectedItems.Count == 0) return;
            try { ApplicationCommands.Copy.Execute(null, grid); } catch { /* clipboard busy */ }
        }

        private static T? FindAncestor<T>(DependencyObject? d) where T : DependencyObject
        {
            while (d != null && d is not T) d = VisualTreeHelper.GetParent(d);
            return d as T;
        }
    }
}
