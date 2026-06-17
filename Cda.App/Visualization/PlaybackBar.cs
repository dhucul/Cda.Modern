using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using Cda.Core.Model;

namespace Cda.App.Visualization
{
    public sealed class WindowChangedEventArgs : EventArgs
    {
        public double Start;
        public double End;
        public bool ByUser; // true: the user moved the cursor (scrub / arrow keys); false: a programmatic SetData
        public WindowChangedEventArgs(double start, double end, bool byUser = false)
        {
            Start = start; End = end; ByUser = byUser;
        }
    }

    /// <summary>
    /// DirectX-free replacement for <c>oVisPlayBar</c>. Shows the trace as a
    /// call-density timeline with a moveable cursor window (the slice of time
    /// whose calls light up in the graph) and an optional selection range.
    ///
    /// Interaction mirrors the original:
    ///   * left click / drag  -> move the cursor window,
    ///   * right drag         -> set a selection range,
    ///   * mouse wheel        -> zoom the visible time span about the cursor.
    /// </summary>
    public sealed class PlaybackBar : FrameworkElement
    {
        public event EventHandler<WindowChangedEventArgs>? WindowChanged;

        private IReadOnlyList<CallRecord> _records = Array.Empty<CallRecord>();
        private double _datasetStart, _datasetEnd;

        // Visible span (zoomable) within the dataset.
        private double _viewStart, _viewEnd;

        private double _cursorTime;
        private double _cursorWidth = 0.02; // fraction of the *visible* span
        private double _selStart = double.NaN, _selEnd = double.NaN;

        private bool _draggingCursor, _draggingSelection;

        private static readonly Brush Bg = Frozen(Color.FromRgb(0x12, 0x16, 0x1D));
        private static readonly Brush Density = Frozen(Color.FromArgb(0xFF, 0x4E, 0x7A, 0xC0));
        private static readonly Brush CursorBand = Frozen(Color.FromArgb(0x55, 0xE0, 0xB3, 0x41));
        private static readonly Pen CursorPen = FrozenPen(Color.FromRgb(0xE0, 0xB3, 0x41), 1.0);
        private static readonly Brush SelectionBand = Frozen(Color.FromArgb(0x33, 0x4D, 0x8D, 0xF7));
        private static readonly Pen AxisPen = FrozenPen(Color.FromArgb(0x55, 0xAE, 0xB7, 0xC4), 1.0);
        private static readonly Pen FocusPen = FrozenPen(Color.FromArgb(0x99, 0x4D, 0x8D, 0xF7), 1.0);

        public PlaybackBar()
        {
            Focusable = true;
            ClipToBounds = true;
            Height = 110;
            FocusVisualStyle = null; // we draw our own subtle focus outline
            ToolTip = "Click to scrub. With focus: ← → nudge the cursor one step " +
                      "(Ctrl = larger), Home / End jump to the ends.";
        }

        public void SetData(TraceDataset data)
        {
            _records = data.Records;
            _datasetStart = data.TimeStart;
            _datasetEnd = data.TimeEnd <= data.TimeStart ? data.TimeStart + 1 : data.TimeEnd;
            _viewStart = _datasetStart;
            _viewEnd = _datasetEnd;
            _cursorTime = (_datasetStart + _datasetEnd) * 0.5; // start mid-trace, over activity
            RaiseWindow();
            InvalidateVisual();
        }

        private double ViewSpan => Math.Max(1e-9, _viewEnd - _viewStart);
        private double TimeToX(double t) => (t - _viewStart) / ViewSpan * ActualWidth;
        private double XToTime(double x) => _viewStart + x / Math.Max(1, ActualWidth) * ViewSpan;

        private void RaiseWindow(bool byUser = false)
        {
            double half = _cursorWidth * ViewSpan * 0.5;
            WindowChanged?.Invoke(this, new WindowChangedEventArgs(_cursorTime - half, _cursorTime + half, byUser));
        }

        // --- interaction -----------------------------------------------------

        protected override void OnMouseDown(MouseButtonEventArgs e)
        {
            Focus();
            CaptureMouse();
            double t = Math.Clamp(XToTime(e.GetPosition(this).X), _viewStart, _viewEnd);
            if (e.ChangedButton == MouseButton.Right)
            {
                _draggingSelection = true;
                _selStart = _selEnd = t;
            }
            else
            {
                _draggingCursor = true;
                _cursorTime = t;
                RaiseWindow(byUser: true);
            }
            InvalidateVisual();
            base.OnMouseDown(e);
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            if (!_draggingCursor && !_draggingSelection) return;
            double t = Math.Clamp(XToTime(e.GetPosition(this).X), _viewStart, _viewEnd);
            if (_draggingSelection)
            {
                _selEnd = t;
            }
            else if (_draggingCursor)
            {
                _cursorTime = t;
                RaiseWindow(byUser: true);
            }
            InvalidateVisual();
            base.OnMouseMove(e);
        }

        protected override void OnMouseUp(MouseButtonEventArgs e)
        {
            _draggingCursor = _draggingSelection = false;
            ReleaseMouseCapture();
            base.OnMouseUp(e);
        }

        protected override void OnMouseWheel(MouseWheelEventArgs e)
        {
            double focus = Math.Clamp(XToTime(e.GetPosition(this).X), _viewStart, _viewEnd);
            double factor = Math.Pow(0.9, e.Delta / 120.0);
            double newSpan = Math.Clamp(ViewSpan * factor, 1e-6, _datasetEnd - _datasetStart);

            double left = focus - (focus - _viewStart) * (newSpan / ViewSpan);
            _viewStart = left;
            _viewEnd = left + newSpan;
            if (_viewStart < _datasetStart) { _viewEnd += _datasetStart - _viewStart; _viewStart = _datasetStart; }
            if (_viewEnd > _datasetEnd) { _viewStart -= _viewEnd - _datasetEnd; _viewEnd = _datasetEnd; }
            if (_viewStart < _datasetStart) _viewStart = _datasetStart;

            RaiseWindow();
            InvalidateVisual();
            e.Handled = true;
        }

        // Keyboard: precise cursor control once the bar has focus (click it first).
        // Left/Right nudge the cursor by one step; Ctrl makes the step larger;
        // Home/End jump to the ends. The visible span pans to keep the cursor on
        // screen when zoomed in, so you can step across the whole trace.
        protected override void OnKeyDown(KeyEventArgs e)
        {
            if (_datasetEnd <= _datasetStart) { base.OnKeyDown(e); return; }

            double step = ViewSpan / Math.Max(1.0, ActualWidth); // one pixel of time
            bool ctrl = (Keyboard.Modifiers & ModifierKeys.Control) != 0;
            double coarse = ViewSpan * 0.05;

            switch (e.Key)
            {
                case Key.Left:  SetCursor(_cursorTime - (ctrl ? coarse : step)); e.Handled = true; break;
                case Key.Right: SetCursor(_cursorTime + (ctrl ? coarse : step)); e.Handled = true; break;
                case Key.Home:  SetCursor(_datasetStart); e.Handled = true; break;
                case Key.End:   SetCursor(_datasetEnd);   e.Handled = true; break;
                default: base.OnKeyDown(e); break;
            }
        }

        // Move the cursor to an absolute time, clamped to the dataset, panning the
        // visible span if needed so the cursor stays on screen.
        private void SetCursor(double t)
        {
            _cursorTime = Math.Clamp(t, _datasetStart, _datasetEnd);

            double span = ViewSpan;
            if (_cursorTime < _viewStart) { _viewStart = _cursorTime; _viewEnd = _viewStart + span; }
            else if (_cursorTime > _viewEnd) { _viewEnd = _cursorTime; _viewStart = _viewEnd - span; }
            if (_viewStart < _datasetStart) { _viewStart = _datasetStart; _viewEnd = _viewStart + span; }
            if (_viewEnd > _datasetEnd) { _viewEnd = _datasetEnd; _viewStart = _viewEnd - span; }
            if (_viewStart < _datasetStart) _viewStart = _datasetStart;

            RaiseWindow(byUser: true);
            InvalidateVisual();
        }

        protected override void OnGotKeyboardFocus(KeyboardFocusChangedEventArgs e)
        {
            base.OnGotKeyboardFocus(e);
            InvalidateVisual();
        }

        protected override void OnLostKeyboardFocus(KeyboardFocusChangedEventArgs e)
        {
            base.OnLostKeyboardFocus(e);
            InvalidateVisual();
        }

        // --- rendering -------------------------------------------------------

        protected override void OnRender(DrawingContext dc)
        {
            double w = ActualWidth, h = ActualHeight;
            dc.DrawRectangle(Bg, null, new Rect(0, 0, w, h));
            if (w <= 0) return;

            DrawDensity(dc, w, h);
            DrawSelection(dc, h);
            DrawCursor(dc, h);
            DrawAxis(dc, w, h);

            if (IsKeyboardFocused && w > 1 && h > 1)
                dc.DrawRectangle(null, FocusPen, new Rect(0.5, 0.5, w - 1, h - 1));
        }

        private void DrawDensity(DrawingContext dc, double w, double h)
        {
            if (_records.Count == 0) return;
            int bins = Math.Max(1, (int)w);
            var counts = new int[bins];
            int max = 1;
            foreach (var r in _records)
            {
                if (r.Time < _viewStart || r.Time > _viewEnd) continue;
                int b = (int)(TimeToX(r.Time));
                if (b < 0) b = 0; else if (b >= bins) b = bins - 1;
                counts[b]++;
                if (counts[b] > max) max = counts[b];
            }
            double baseY = h - 16;
            for (int x = 0; x < bins; x++)
            {
                if (counts[x] == 0) continue;
                double bh = counts[x] / (double)max * (baseY - 4);
                dc.DrawRectangle(Density, null, new Rect(x, baseY - bh, 1, bh));
            }
        }

        private void DrawCursor(DrawingContext dc, double h)
        {
            double half = _cursorWidth * ViewSpan * 0.5;
            double x0 = TimeToX(_cursorTime - half);
            double x1 = TimeToX(_cursorTime + half);
            if (x1 - x0 < 1) x1 = x0 + 1;
            dc.DrawRectangle(CursorBand, null, new Rect(x0, 0, x1 - x0, h - 16));
            double xc = TimeToX(_cursorTime);
            dc.DrawLine(CursorPen, new Point(xc, 0), new Point(xc, h - 16));
        }

        private void DrawSelection(DrawingContext dc, double h)
        {
            if (double.IsNaN(_selStart) || double.IsNaN(_selEnd)) return;
            double a = TimeToX(Math.Min(_selStart, _selEnd));
            double b = TimeToX(Math.Max(_selStart, _selEnd));
            dc.DrawRectangle(SelectionBand, null, new Rect(a, 0, Math.Max(1, b - a), h - 16));
        }

        private void DrawAxis(DrawingContext dc, double w, double h)
        {
            dc.DrawLine(AxisPen, new Point(0, h - 16), new Point(w, h - 16));
            int ticks = 8;
            var tf = new Typeface("Segoe UI");
            double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
            for (int i = 0; i <= ticks; i++)
            {
                double x = w * i / ticks;
                dc.DrawLine(AxisPen, new Point(x, h - 16), new Point(x, h - 11));
                double t = XToTime(x);
                var ft = new FormattedText(t.ToString("0.000") + "s",
                    System.Globalization.CultureInfo.CurrentUICulture,
                    FlowDirection.LeftToRight, tf, 9,
                    new SolidColorBrush(Color.FromArgb(0xAA, 0xAE, 0xB7, 0xC4)), dpi);
                double tx = Math.Min(Math.Max(0, x - ft.Width / 2), w - ft.Width);
                dc.DrawText(ft, new Point(tx, h - 11));
            }
        }

        private static Brush Frozen(Color c) { var b = new SolidColorBrush(c); b.Freeze(); return b; }
        private static Pen FrozenPen(Color c, double t)
        {
            var p = new Pen(new SolidColorBrush(c), t); p.Freeze(); return p;
        }
    }
}
