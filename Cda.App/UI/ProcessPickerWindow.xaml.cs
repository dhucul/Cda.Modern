using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Threading.Tasks;
using Cda.Core.Process;

namespace Cda.App.UI
{
    /// <summary>
    /// Modal process picker for the Attach flow. Lists running processes with
    /// best-effort bitness; the selection drives a read-only <c>LiveSession</c>.
    /// </summary>
    public partial class ProcessPickerWindow : Window
    {
        private List<ProcessEntry> _all = new();
        private ICollectionView? _view;
        private string _filter = "";

        public int SelectedPid { get; private set; } = -1;
        public ProcessEntry? SelectedEntry { get; private set; }

        public ProcessPickerWindow()
        {
            InitializeComponent();
            Loaded += async (_, _) => await ReloadAsync();
        }

        private async Task ReloadAsync()
        {
            List.ItemsSource = null;
            _all = await Task.Run(ProcessList.Enumerate);
            _view = CollectionViewSource.GetDefaultView(_all);
            _view.Filter = o =>
            {
                if (_filter.Length == 0) return true;
                if (o is not ProcessEntry e) return false;
                return e.Name.Contains(_filter, StringComparison.OrdinalIgnoreCase)
                    || e.Pid.ToString().Contains(_filter);
            };
            List.ItemsSource = _view;
        }

        private async void OnRefresh(object sender, RoutedEventArgs e) => await ReloadAsync();

        private void OnFilterChanged(object sender, TextChangedEventArgs e)
        {
            _filter = Filter.Text ?? "";
            _view?.Refresh();
        }

        private void OnAttach(object sender, RoutedEventArgs e)
        {
            if (List.SelectedItem is ProcessEntry entry)
            {
                SelectedEntry = entry;
                SelectedPid = entry.Pid;
                DialogResult = true;
                Close();
            }
        }

        private void OnListDoubleClick(object sender, MouseButtonEventArgs e) => OnAttach(sender, e);

        private void OnCancel(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
