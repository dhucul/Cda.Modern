using System.Collections.ObjectModel;
using System.Windows.Controls;
using Cda.Core.Cpu;
using Cda.Core.Model;
using Cda.Core.Process;

namespace Cda.App.UI
{
    public sealed class ArgumentRow
    {
        public string Index { get; init; } = "";
        public string Slot { get; init; } = "";
        public string Value { get; init; } = "";
        public string Deref { get; init; } = "";
    }

    /// <summary>
    /// Decodes and displays the captured arguments of a single call — the modern
    /// equivalent of the legacy argument/dereference rendering in
    /// <c>oFunction.getArgumentString</c> + the <c>dereference</c> type. It maps
    /// captured integer values to their calling-convention slots using the
    /// architecture's <see cref="ArgumentLayout"/> and surfaces any string the
    /// engine followed a pointer to.
    /// </summary>
    public partial class ArgumentInspector : UserControl
    {
        private readonly ObservableCollection<ArgumentRow> _rows = new();
        private ModuleMap? _map;
        private bool _is64;

        public ArgumentInspector()
        {
            InitializeComponent();
            Grid.ItemsSource = _rows;
            GridCopy.Enable(Grid);
        }

        public void Configure(ModuleMap? map, bool is64Bit)
        {
            _map = map;
            _is64 = is64Bit;
        }

        /// <summary>Clear the grid and show a status line (e.g. "waiting for calls").</summary>
        public void ShowMessage(string text)
        {
            _rows.Clear();
            Header.Text = text;
        }

        public void Show(CallRecord record)
        {
            _rows.Clear();
            string src = _map?.Describe(record.Source) ?? "0x" + record.Source.ToString("X");
            string dst = _map?.Describe(record.Destination) ?? "0x" + record.Destination.ToString("X");
            Header.Text = $"{src}  →  {dst}\nt = {record.Time:0.000}s   sp = 0x{record.StackPointer:X}";

            var layout = CpuArchitectures.For(_is64).GetDefaultArgumentLayout();
            int width = _is64 ? 16 : 8;

            for (int i = 0; i < record.IntegerArgs.Length; i++)
            {
                string slot = i < layout.RegisterArgs.Length
                    ? layout.RegisterArgs[i]
                    : "[sp+0x" + (layout.FirstStackArgOffset + (i - layout.RegisterArgs.Length) * layout.PointerSize).ToString("X") + "]";

                string deref = "";
                foreach (var d in record.Dereferences)
                {
                    if (d.ArgumentIndex != i) continue;
                    var s = d.AsString();
                    deref = s != null ? "\"" + s + "\"" : "→ 0x" + d.Pointer.ToString("X");
                    break;
                }

                _rows.Add(new ArgumentRow
                {
                    Index = i.ToString(),
                    Slot = slot,
                    Value = "0x" + record.IntegerArgs[i].ToString("X" + width),
                    Deref = deref,
                });
            }

            if (record.IntegerArgs.Length == 0)
                Header.Text += "\n(this record carries no captured arguments)";
        }
    }
}
