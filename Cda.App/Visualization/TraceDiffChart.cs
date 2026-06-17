using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using Cda.Core.Engine;

namespace Cda.App.Visualization
{
    /// <summary>
    /// "Where they differ" graph: a diverging horizontal bar chart of the functions
    /// whose observed call count changed between two traces, most-divergent first.
    /// A bar grows right and green when the function ran more in B (or is new in B),
    /// left and red when it ran fewer times (or was removed). Pure WPF vector
    /// drawing, so it stays crisp at any 4K/5K scale and matches the call graph.
    /// Clicking a bar raises <see cref="BarSelected"/>.
    /// </summary>
    public sealed class TraceDiffChart : FrameworkElement
    {
        private IReadOnlyList<FunctionDiff> _items = Array.Empty<FunctionDiff>();
        private long _maxAbs = 1;

        private readonly List<Hit> _hits = new();
        private FunctionDiff? _hover;

        private readonly struct Hit
        {
            public readonly Rect Rect;
            public readonly FunctionDiff Item;
            public Hit(Rect rect, FunctionDiff item) { Rect = rect; Item = item; }
        }

        /// <summary>Raised when the user clicks a bar (or its label).</summary>
        public event EventHandler<FunctionDiff>? BarSelected;

        // --- palette (frozen) ----------------------------------------------
        private static readonly Brush Bg = VisualTheme.Background;
        private static readonly Brush MoreFill = Frozen(Color.FromRgb(0x3F, 0xB9, 0x50)); // green: more in B / new
        private static readonly Brush LessFill = Frozen(Color.FromRgb(0xF8, 0x51, 0x49)); // red: fewer in B / removed
        private static readonly Brush LabelText = Frozen(Color.FromRgb(0xE6, 0xEA, 0xF0));
        private static readonly Brush SubText = Frozen(Color.FromRgb(0xAE, 0xB7, 0xC4));
        private static readonly Brush HintText = Frozen(Color.FromRgb(0x79, 0x82, 0x8F));
        private static readonly Pen ZeroPen = FrozenPen(Color.FromRgb(0x3A, 0x44, 0x52), 1.0);
        private static readonly Pen HoverPen = FrozenPen(Color.FromRgb(0xE6, 0xEA, 0xF0), 1.4);

        private readonly Typeface _face =
            new(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
        private readonly Typeface _faceSemi =
            new(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal);
        private readonly Typeface _mono =
            new(new FontFamily("Cascadia Mono, Consolas"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);

        public TraceDiffChart()
        {
            ClipToBounds = true;
            Focusable = true;
        }

        /// <summary>Set the rows to chart (already sorted by |Delta| descending).</summary>
        public void SetItems(IReadOnlyList<FunctionDiff> items)
        {
            _items = items ?? Array.Empty<FunctionDiff>();
            _maxAbs = 1;
            foreach (var d in _items) if (d.AbsDelta > _maxAbs) _maxAbs = d.AbsDelta;
            InvalidateVisual();
        }

        protected override void OnRenderSizeChanged(SizeChangedInfo info)
        {
            base.OnRenderSizeChanged(info);
            InvalidateVisual();
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            Point p = e.GetPosition(this);
            FunctionDiff? over = null;
            foreach (var h in _hits)
                if (h.Rect.Contains(p)) { over = h.Item; break; }
            if (!ReferenceEquals(over, _hover))
            {
                _hover = over;
                Cursor = over != null ? Cursors.Hand : Cursors.Arrow;
                InvalidateVisual();
            }
            base.OnMouseMove(e);
        }

        protected override void OnMouseDown(MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
            {
                Focus();
                Point p = e.GetPosition(this);
                foreach (var h in _hits)
                    if (h.Rect.Contains(p)) { BarSelected?.Invoke(this, h.Item); break; }
            }
            base.OnMouseDown(e);
        }

        // --- rendering ------------------------------------------------------

        protected override void OnRender(DrawingContext dc)
        {
            double W = ActualWidth, H = ActualHeight;
            dc.DrawRectangle(Bg, null, new Rect(0, 0, W, H));
            _hits.Clear();
            if (W <= 0 || H <= 0) return;

            double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;

            if (_items.Count == 0)
            {
                DrawCentredHint(dc, W, H, dpi,
                    "No call-count differences to chart — the two traces ran the same functions the same number of times, or nothing matched the filter.");
                return;
            }

            const double margin = 12;
            const double legendH = 26;

            // Legend.
            DrawLegend(dc, margin, margin, dpi);

            double top = margin + legendH;
            double labelW = Math.Clamp(W * 0.42, 120, 320);
            double barLeft = margin + labelW + 8;
            double barRight = W - margin;
            if (barRight - barLeft < 60) { DrawCentredHint(dc, W, H, dpi, "Widen this panel to see the diff chart."); return; }

            double zeroX = (barLeft + barRight) / 2;
            double halfW = (barRight - barLeft) / 2 - 8;

            // How many rows fit (each at a comfortable pitch), capped by the data.
            // Reserve a line at the bottom for the "+N more" footer when truncating,
            // so it doesn't overlap the last bar.
            double avail = H - top - margin;
            double pitch = 26;
            int fit = Math.Max(1, (int)(avail / pitch));
            bool truncated = _items.Count > fit;
            if (truncated) { avail = Math.Max(pitch, avail - 18); fit = Math.Max(1, (int)(avail / pitch)); }
            int n = Math.Min(_items.Count, fit);
            if (n < _items.Count) pitch = avail / n; // stretch to fill if data exceeds slots only mildly
            double barH = Math.Clamp(pitch - 8, 12, 22);

            // Zero line.
            dc.DrawLine(ZeroPen, new Point(zeroX, top), new Point(zeroX, top + n * pitch));

            for (int i = 0; i < n; i++)
            {
                var d = _items[i];
                double cy = top + pitch * (i + 0.5);

                // Label (function name), right-aligned to the bar's left edge.
                string label = d.Label;
                var ftLabel = Text(label, _faceSemi, 12, LabelText, dpi, labelW, true);
                dc.DrawText(ftLabel, new Point(barLeft - 8 - ftLabel.WidthIncludingTrailingWhitespace,
                                               cy - ftLabel.Height / 2));

                // Bar, proportional to |delta| / maxAbs.
                double len = _maxAbs > 0 ? (double)d.AbsDelta / _maxAbs * halfW : 0;
                len = Math.Max(len, 2); // keep a sliver visible even for a delta of 1
                bool more = d.Delta >= 0;
                Brush fill = more ? MoreFill : LessFill;
                Rect bar = more
                    ? new Rect(zeroX, cy - barH / 2, len, barH)
                    : new Rect(zeroX - len, cy - barH / 2, len, barH);

                bool hot = ReferenceEquals(d, _hover);
                dc.DrawRoundedRectangle(fill, hot ? HoverPen : null, bar, 3, 3);

                // Value annotation at the outer end of the bar: signed delta + A→B.
                string sign = d.Delta > 0 ? "+" : "";
                string val = $"{sign}{d.Delta:N0}";
                string ctx = StatusSuffix(d);
                var ftVal = Text(val + ctx, _mono, 11, SubText, dpi, halfW, false);
                double vx = more ? bar.Right + 6 : bar.Left - 6 - ftVal.WidthIncludingTrailingWhitespace;
                // Keep the annotation on-canvas if the bar reaches the edge. Done with
                // explicit Min/Max (not Math.Clamp, which throws when the upper bound
                // falls below the lower one for a wide label in a narrow bar area).
                double maxVx = barRight - ftVal.WidthIncludingTrailingWhitespace;
                vx = Math.Max(barLeft, Math.Min(vx, maxVx));
                dc.DrawText(ftVal, new Point(vx, cy - ftVal.Height / 2));

                // Whole-row hit target (label + bar area).
                _hits.Add(new Hit(new Rect(margin, cy - pitch / 2, W - 2 * margin, pitch), d));
            }

            if (n < _items.Count)
            {
                var more = Text($"+ {_items.Count - n:N0} more differing function(s) — see the table on the left",
                    _face, 10.5, HintText, dpi, W - 2 * margin, true);
                dc.DrawText(more, new Point(margin, H - margin - more.Height + 2));
            }
        }

        private static string StatusSuffix(FunctionDiff d) => d.Status switch
        {
            TraceDiffStatus.OnlyB => "  (new in B)",
            TraceDiffStatus.OnlyA => "  (removed)",
            _ => $"   {d.CountA:N0}→{d.CountB:N0}",
        };

        private void DrawLegend(DrawingContext dc, double x, double y, double dpi)
        {
            double sw = 12, gap = 6;
            dc.DrawRoundedRectangle(MoreFill, null, new Rect(x, y + 1, sw, sw), 2, 2);
            var t1 = Text("more in B / new", _face, 11, SubText, dpi, 200, false);
            dc.DrawText(t1, new Point(x + sw + gap, y - 1));
            double x2 = x + sw + gap + t1.WidthIncludingTrailingWhitespace + 18;
            dc.DrawRoundedRectangle(LessFill, null, new Rect(x2, y + 1, sw, sw), 2, 2);
            var t2 = Text("fewer in B / removed", _face, 11, SubText, dpi, 220, false);
            dc.DrawText(t2, new Point(x2 + sw + gap, y - 1));
        }

        private void DrawCentredHint(DrawingContext dc, double W, double H, double dpi, string text)
        {
            double maxW = Math.Min(W - 40, 520);
            var ft = new FormattedText(text, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight,
                _face, 13, HintText, dpi)
            { TextAlignment = TextAlignment.Center, MaxTextWidth = Math.Max(40, maxW) };
            dc.DrawText(ft, new Point(W / 2 - ft.MaxTextWidth / 2, H / 2 - ft.Height / 2));
        }

        private FormattedText Text(string s, Typeface tf, double size, Brush brush, double dpi, double maxW, bool ellipsis)
        {
            var ft = new FormattedText(s ?? "", CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, tf, size, brush, dpi);
            if (maxW > 0)
            {
                ft.MaxTextWidth = Math.Max(8, maxW);
                ft.MaxLineCount = 1;
                if (ellipsis) ft.Trimming = TextTrimming.CharacterEllipsis;
            }
            return ft;
        }

        private static Brush Frozen(Color c) { var b = new SolidColorBrush(c); b.Freeze(); return b; }
        private static Pen FrozenPen(Color c, double t) { var p = new Pen(new SolidColorBrush(c), t); p.Freeze(); return p; }
    }
}
