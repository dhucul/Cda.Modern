using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using Cda.Core.Cpu;
using Cda.Core.Memory;

namespace Cda.App.UI
{
    /// <summary>
    /// A lightweight instruction view: the selected function decoded and
    /// MASM-formatted (address · bytes · mnemonic), the disassembler counterpart
    /// to <see cref="HexView"/>. It reads bytes on demand through the same
    /// <see cref="IMemorySource"/> the hex view uses (a mapped file image or a live
    /// process) and decodes with Iced via the architecture seam, so one control
    /// serves x86 and x64. A function is bounded, so it decodes a single window
    /// (stopping at the first ret/jmp/int3) rather than virtualizing an address
    /// space — only the visible lines are drawn.
    ///
    /// It also has a plain-text mode (<see cref="ShowText"/>) used to render managed
    /// method IL / decompiled C# in the same pane.
    /// </summary>
    public sealed class DisasmView : Grid
    {
        private readonly Surface _surface;
        private readonly ScrollBar _scroll;
        private readonly ScrollBar _hScroll;
        private double _xOffset; // horizontal scroll offset, in pixels

        private IMemorySource? _source;
        private readonly List<Line> _lines = new();
        private int _top; // index of the first visible line

        /// <summary>Bytes decoded for one function (a generous single-function window).</summary>
        private const int MaxDecodeBytes = 4096;

        // Shared with the rest of the app via AppFonts (see AppFonts.cs).
        private readonly Typeface _typeface = AppFonts.MonoRegular;
        private const double FontSize = 13.0;
        private double _rowHeight = 16;
        private double _charWidth = 8;

        // How many instruction bytes to show before eliding (keeps the mnemonic column aligned).
        private const int MaxShownBytes = 8;

        private static readonly Brush BgBrush = Frozen(Color.FromRgb(0x1B, 0x1E, 0x24));
        private static readonly Brush AddrBrush = Frozen(Color.FromRgb(0x7F, 0xA3, 0xCF));
        private static readonly Brush BytesBrush = Frozen(Color.FromRgb(0x54, 0x5C, 0x69));
        private static readonly Brush TextBrush = Frozen(Color.FromRgb(0xC6, 0xCD, 0xD8));
        private static readonly Brush PlainBrush = Frozen(Color.FromRgb(0xA7, 0xB0, 0xBD));

        private readonly struct Line
        {
            public readonly string Addr;
            public readonly string Bytes;
            public readonly string Text;
            public readonly bool Plain; // a full-width text line (IL / C#), no addr/bytes columns

            public Line(string addr, string bytes, string text, bool plain)
            {
                Addr = addr; Bytes = bytes; Text = text; Plain = plain;
            }
        }

        public DisasmView()
        {
            ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            _surface = new Surface(this);
            SetColumn(_surface, 0);
            SetRow(_surface, 0);
            Children.Add(_surface);

            _scroll = new ScrollBar { Orientation = Orientation.Vertical, SmallChange = 1 };
            _scroll.Scroll += OnScroll;
            SetColumn(_scroll, 1);
            SetRow(_scroll, 0);
            Children.Add(_scroll);

            _hScroll = new ScrollBar { Orientation = Orientation.Horizontal, Visibility = Visibility.Collapsed };
            _hScroll.Scroll += OnHScroll;
            SetColumn(_hScroll, 0);
            SetRow(_hScroll, 1);
            Children.Add(_hScroll);

            var copy = new MenuItem { Header = "Copy", InputGestureText = "Ctrl+C" };
            copy.Click += (_, _) => CopyAll();
            _surface.ContextMenu = new ContextMenu();
            _surface.ContextMenu.Items.Add(copy);

            MeasureFont();
        }

        /// <summary>Set the byte source (mapped file image or live process). Mirrors HexView.</summary>
        public void SetSource(IMemorySource? source, ulong startAddress = 0)
        {
            _source = source;
            _lines.Clear();
            _top = 0;
            ConfigureScroll();
            _surface.InvalidateVisual();
        }

        /// <summary>
        /// Disassemble the function at <paramref name="virtualAddress"/>, reading bytes
        /// from the current source at <paramref name="readAddress"/> (a file offset for a
        /// mapped image, the same VA for a live process).
        /// </summary>
        public void ShowFunction(ulong virtualAddress, ulong readAddress)
        {
            _lines.Clear();
            _top = 0;

            if (_source != null)
            {
                var arch = CpuArchitectures.For(_source.Is64Bit);
                var decoded = arch.FormatRange(_source, readAddress, virtualAddress, MaxDecodeBytes);
                int digits = _source.Is64Bit ? 16 : 8;
                foreach (var d in decoded)
                    _lines.Add(new Line(d.Address.ToString("X" + digits), FormatBytes(d.Bytes), d.Text, plain: false));

            }

            if (_lines.Count == 0)
                _lines.Add(new Line("", "", _source == null
                    ? "; no byte source — open a module or attach to a process"
                    : "; no decodable instructions at this address", plain: true));

            ConfigureScroll();
            _surface.InvalidateVisual();
        }

        /// <summary>Show arbitrary text lines (managed IL / decompiled C#) in the same pane.</summary>
        public void ShowText(IEnumerable<string> textLines)
        {
            _lines.Clear();
            _top = 0;
            foreach (var t in textLines)
                _lines.Add(new Line("", "", t, plain: true));
            ConfigureScroll();
            _surface.InvalidateVisual();
        }

        public void Clear()
        {
            _lines.Clear();
            _top = 0;
            ConfigureScroll();
            _surface.InvalidateVisual();
        }

        private static string FormatBytes(byte[] b)
        {
            var sb = new StringBuilder(MaxShownBytes * 3 + 1);
            int n = Math.Min(b.Length, MaxShownBytes);
            for (int i = 0; i < n; i++) { sb.Append(b[i].ToString("X2")); sb.Append(' '); }
            if (b.Length > MaxShownBytes) sb.Append('+');
            return sb.ToString();
        }

        private int VisibleRows => Math.Max(1, (int)(_surface.ActualHeight / _rowHeight));

        private void MeasureFont()
        {
            var ft = new FormattedText("0", CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                _typeface, FontSize, Brushes.White, 1.0);
            _charWidth = ft.WidthIncludingTrailingWhitespace;
            _rowHeight = Math.Ceiling(ft.Height) + 2;
        }

        private void ConfigureScroll()
        {
            _scroll.Minimum = 0;
            _scroll.Maximum = Math.Max(0, _lines.Count - VisibleRows);
            _scroll.LargeChange = VisibleRows;
            _scroll.SmallChange = 1;
            _scroll.ViewportSize = VisibleRows;
            if (_top > (int)_scroll.Maximum) _top = (int)_scroll.Maximum;
            _scroll.Value = _top;

            ConfigureHScroll();
        }

        // The widest rendered line drives the horizontal bar; it appears only when a
        // line (e.g. a long decompiled-C# statement) runs past the pane's right edge.
        private void ConfigureHScroll()
        {
            int addrDigits = _source != null && _source.Is64Bit ? 16 : 8;
            double bytesX = 6 + (addrDigits + 2) * _charWidth;
            double textX = bytesX + (MaxShownBytes * 3 + 2) * _charWidth;
            double content = 0;
            foreach (var l in _lines)
            {
                double right = (l.Plain ? 6 : textX) + l.Text.Length * _charWidth;
                if (right > content) content = right;
            }
            if (_lines.Count > 0) content += 8;

            double viewport = _surface.ActualWidth;
            double max = Math.Max(0, content - viewport);
            _hScroll.Minimum = 0;
            _hScroll.Maximum = max;
            _hScroll.ViewportSize = viewport;
            _hScroll.LargeChange = Math.Max(_charWidth, viewport - _charWidth);
            _hScroll.SmallChange = _charWidth;
            if (_xOffset > max) _xOffset = max;
            _hScroll.Value = _xOffset;
            _hScroll.Visibility = viewport > 0.5 && max > 0.5 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void OnHScroll(object sender, ScrollEventArgs e)
        {
            _xOffset = Math.Max(0, Math.Min(e.NewValue, _hScroll.Maximum));
            _surface.InvalidateVisual();
        }

        private void ScrollHoriz(double dx)
        {
            double v = Math.Max(0, Math.Min(_xOffset + dx, _hScroll.Maximum));
            if (v == _xOffset) return;
            _xOffset = v;
            _hScroll.Value = v;
            _surface.InvalidateVisual();
        }

        private void OnScroll(object sender, ScrollEventArgs e)
        {
            _top = (int)Math.Max(0, e.NewValue);
            _surface.InvalidateVisual();
        }

        private void ScrollByRows(int rows)
        {
            int max = Math.Max(0, _lines.Count - VisibleRows);
            _top = Math.Clamp(_top + rows, 0, max);
            _scroll.Value = _top;
            _surface.InvalidateVisual();
        }

        private void CopyAll()
        {
            var sb = new StringBuilder();
            foreach (var l in _lines)
            {
                if (l.Plain) sb.AppendLine(l.Text);
                else sb.Append(l.Addr).Append("  ").Append(l.Bytes.PadRight(MaxShownBytes * 3 + 1))
                       .Append("  ").AppendLine(l.Text);
            }
            try { Clipboard.SetText(sb.ToString()); } catch { /* clipboard busy */ }
        }

        // --- rendering ------------------------------------------------------

        private void Render(DrawingContext dc, double width, double height)
        {
            dc.DrawRectangle(BgBrush, null, new Rect(0, 0, width, height));
            if (_lines.Count == 0) return;

            dc.PushTransform(new TranslateTransform(-_xOffset, 0));

            double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
            int addrDigits = _source != null && _source.Is64Bit ? 16 : 8;
            double bytesX = 6 + (addrDigits + 2) * _charWidth;
            double textX = bytesX + (MaxShownBytes * 3 + 2) * _charWidth;

            int rows = (int)(height / _rowHeight) + 1;
            for (int r = 0; r < rows; r++)
            {
                int idx = _top + r;
                if (idx >= _lines.Count) break;
                var line = _lines[idx];
                double y = r * _rowHeight;

                if (line.Plain)
                {
                    Draw(dc, line.Text, 6, y, PlainBrush, dpi);
                    continue;
                }
                Draw(dc, line.Addr, 6, y, AddrBrush, dpi);
                Draw(dc, line.Bytes, bytesX, y, BytesBrush, dpi);
                Draw(dc, line.Text, textX, y, TextBrush, dpi);
            }

            dc.Pop();
        }

        private void Draw(DrawingContext dc, string text, double x, double y, Brush brush, double dpi)
        {
            if (string.IsNullOrEmpty(text)) return;
            var ft = new FormattedText(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                _typeface, FontSize, brush, dpi);
            dc.DrawText(ft, new Point(x, y));
        }

        private static Brush Frozen(Color c) { var b = new SolidColorBrush(c); b.Freeze(); return b; }

        /// <summary>Inner element that owns the draw surface + input.</summary>
        private sealed class Surface : FrameworkElement
        {
            private readonly DisasmView _owner;

            public Surface(DisasmView owner) { _owner = owner; ClipToBounds = true; Focusable = true; }

            protected override void OnRenderSizeChanged(SizeChangedInfo info)
            {
                base.OnRenderSizeChanged(info);
                _owner.ConfigureScroll();
            }

            protected override void OnMouseWheel(MouseWheelEventArgs e)
            {
                if ((Keyboard.Modifiers & ModifierKeys.Shift) != 0)
                    _owner.ScrollHoriz(-Math.Sign(e.Delta) * 3 * _owner._charWidth);
                else
                    _owner.ScrollByRows(-Math.Sign(e.Delta) * 3);
                e.Handled = true;
            }

            protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
            {
                Focus();
                e.Handled = true;
            }

            protected override void OnKeyDown(KeyEventArgs e)
            {
                switch (e.Key)
                {
                    case Key.Up: _owner.ScrollByRows(-1); e.Handled = true; break;
                    case Key.Down: _owner.ScrollByRows(1); e.Handled = true; break;
                    case Key.PageUp: _owner.ScrollByRows(-_owner.VisibleRows); e.Handled = true; break;
                    case Key.PageDown: _owner.ScrollByRows(_owner.VisibleRows); e.Handled = true; break;
                    case Key.Left: _owner.ScrollHoriz(-4 * _owner._charWidth); e.Handled = true; break;
                    case Key.Right: _owner.ScrollHoriz(4 * _owner._charWidth); e.Handled = true; break;
                    case Key.C when (Keyboard.Modifiers & ModifierKeys.Control) != 0:
                        _owner.CopyAll(); e.Handled = true; break;
                }
            }

            protected override void OnRender(DrawingContext dc)
                => _owner.Render(dc, ActualWidth, ActualHeight);
        }
    }
}
