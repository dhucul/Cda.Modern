using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using Cda.App.Model;

namespace Cda.App.Visualization
{
    /// <summary>
    /// A caller/callee ("butterfly") view of the captured trace, centred on the
    /// selected function.
    ///
    /// The previous renderer drew every discovered function as an unlabelled
    /// square tiled in discovery order, with edges only for the current playback
    /// slice — position carried no meaning, you couldn't tell one dot from
    /// another, and most of the time no edges showed at all. This view answers
    /// the question dynamic analysis actually asks: who calls this function, what
    /// does it call, and how often.
    ///
    ///   * centre — the selected function (total calls in / out),
    ///   * left   — its callers (resolved from each call's return address),
    ///   * right  — its callees,
    /// each labelled and weighted by observed call count. Every edge carries an
    /// arrowhead at the called end and the whole graph reads left-to-right (caller
    /// → function → callee), so the direction of each call is unambiguous. Clicking
    /// a neighbour re-centres the view on it (and selects it everywhere else). Pure
    /// WPF vector drawing, so it stays crisp at any 4K/5K scale.
    ///
    /// <para><b>Diff mode.</b> When a comparison is active (see
    /// <see cref="SetDiffMode"/>), the neighbourhood is built from the trace diff
    /// instead of the live trace: each caller/callee node and edge is recoloured by
    /// how that relationship changed between the two traces — green for more calls
    /// (or new), red for fewer (or removed), grey for unchanged — and labelled with
    /// its A→B counts. It is the edge-level diff drawn straight onto the butterfly.</para>
    /// </summary>
    public sealed class CallGraphView : FrameworkElement
    {
        private CallGraphModel? _model;
        private ulong _selected;
        private CallNeighborhood? _nb;
        private DateTime _lastCompute;

        // When set, the neighbourhood is built from this (the trace diff) rather than
        // the live model; returning null lets the live model take over for a centre
        // the comparison doesn't cover.
        private Func<ulong, CallNeighborhood?>? _diffBuilder;

        // Laid-out, clickable neighbour boxes for the current frame.
        private readonly List<Hit> _hits = new();
        private ulong _hover;

        private readonly struct Hit
        {
            public readonly Rect Rect;
            public readonly ulong Address;
            public Hit(Rect rect, ulong address) { Rect = rect; Address = address; }
        }

        /// <summary>Raised when the user clicks a caller/callee box.</summary>
        public event EventHandler<ulong>? NeighborSelected;

        // --- palette (frozen) ----------------------------------------------
        private static readonly Brush Bg = VisualTheme.Background;
        private static readonly Brush NodeFill = Frozen(Color.FromRgb(0x1B, 0x22, 0x30));
        private static readonly Brush NodeText = Frozen(Color.FromRgb(0xE6, 0xEA, 0xF0));
        private static readonly Brush SubText = Frozen(Color.FromRgb(0xAE, 0xB7, 0xC4));
        private static readonly Brush HintText = Frozen(Color.FromRgb(0x79, 0x82, 0x8F));
        private static readonly Brush CallerBrush = Frozen(VisualTheme.LinkSource);
        private static readonly Brush CalleeBrush = Frozen(VisualTheme.LinkDest);
        private static readonly Brush CenterBrush = Frozen(Color.FromRgb(0xE0, 0xB3, 0x41));
        private static readonly Pen CallerPen = FrozenPen(VisualTheme.LinkSource, 1.4);
        private static readonly Pen CalleePen = FrozenPen(VisualTheme.LinkDest, 1.4);
        private static readonly Pen CenterPen = FrozenPen(Color.FromRgb(0xE0, 0xB3, 0x41), 1.6);
        private static readonly Pen HoverPen = FrozenPen(Color.FromRgb(0xE6, 0xEA, 0xF0), 1.6);

        // Diff palette: green = more / new, red = fewer / removed, grey = unchanged.
        private static readonly Color MoreColor = Color.FromRgb(0x3F, 0xB9, 0x50);
        private static readonly Color LessColor = Color.FromRgb(0xF8, 0x51, 0x49);
        private static readonly Color SameColor = Color.FromRgb(0x6A, 0x73, 0x80);
        private static readonly Brush MoreBrush = Frozen(MoreColor);
        private static readonly Brush LessBrush = Frozen(LessColor);
        private static readonly Brush SameBrush = Frozen(SameColor);
        private static readonly Pen MorePen = FrozenPen(MoreColor, 1.6);
        private static readonly Pen LessPen = FrozenPen(LessColor, 1.6);
        private static readonly Pen SamePen = FrozenPen(SameColor, 1.2);

        private readonly Typeface _face =
            new(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
        private readonly Typeface _faceSemi =
            new(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal);
        private readonly Typeface _mono =
            new(new FontFamily("Cascadia Mono, Consolas"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);

        public CallGraphView()
        {
            ClipToBounds = true;
            Focusable = true;
        }

        public void SetModel(CallGraphModel model)
        {
            _model = model;
            _selected = 0;
            _nb = null;
            InvalidateVisual();
        }

        /// <summary>
        /// Switch the view between the live butterfly and a trace-diff butterfly.
        /// Pass a builder (e.g. <c>GraphDiff.Build</c>) to enter diff mode, or null to
        /// leave it. Recomputes the current centre immediately.
        /// </summary>
        public void SetDiffMode(Func<ulong, CallNeighborhood?>? diffBuilder)
        {
            _diffBuilder = diffBuilder;
            Recompute();
            InvalidateVisual();
        }

        /// <summary>True while a comparison overlay is active.</summary>
        public bool IsDiffMode => _diffBuilder != null;

        /// <summary>Centre the view on a function and (re)build its neighbourhood.</summary>
        public void SetSelected(ulong address)
        {
            _selected = address;
            Recompute();
            InvalidateVisual();
        }

        /// <summary>
        /// Called when the trace changes (a capture poll) or the playback window
        /// moves. Refreshes the live counts, throttled so a fast poll over a large
        /// trace doesn't rebuild the aggregate on every tick.
        /// </summary>
        public void RefreshActive()
        {
            if (_model != null && _selected != 0 &&
                (DateTime.UtcNow - _lastCompute).TotalMilliseconds > 180)
                Recompute();
            InvalidateVisual();
        }

        public void FitToContent() => InvalidateVisual();

        private void Recompute()
        {
            if (_selected == 0) { _nb = null; _lastCompute = DateTime.UtcNow; return; }

            // Diff mode: build from the comparison. A null result (the centre isn't in
            // the compared trace) falls back to the live neighbourhood so a fresh
            // selection still renders.
            CallNeighborhood? nb = _diffBuilder?.Invoke(_selected);
            nb ??= _model?.BuildNeighborhood(_selected);
            _nb = nb;
            _lastCompute = DateTime.UtcNow;
        }

        protected override void OnRenderSizeChanged(SizeChangedInfo info)
        {
            base.OnRenderSizeChanged(info);
            InvalidateVisual();
        }

        // --- interaction ----------------------------------------------------

        protected override void OnMouseDown(MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
            {
                Focus();
                Point p = e.GetPosition(this);
                foreach (var h in _hits)
                    if (h.Rect.Contains(p))
                    {
                        if (h.Address != 0 && h.Address != _selected)
                            NeighborSelected?.Invoke(this, h.Address);
                        break;
                    }
            }
            base.OnMouseDown(e);
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            Point p = e.GetPosition(this);
            ulong over = 0;
            foreach (var h in _hits)
                if (h.Rect.Contains(p)) { over = h.Address; break; }

            if (over != _hover)
            {
                _hover = over;
                Cursor = over != 0 ? Cursors.Hand : Cursors.Arrow;
                InvalidateVisual();
            }
            base.OnMouseMove(e);
        }

        // --- rendering ------------------------------------------------------

        protected override void OnRender(DrawingContext dc)
        {
            double W = ActualWidth, H = ActualHeight;
            dc.DrawRectangle(Bg, null, new Rect(0, 0, W, H));
            _hits.Clear();
            if (W <= 0 || H <= 0) return;

            double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;

            if (_model == null || _selected == 0 || _nb == null)
            {
                DrawCentredHint(dc, W, H, dpi, IsDiffMode
                    ? "Select a function to see how its callers and callees differ between the two traces."
                    : "Select a function on the left to see who calls it and what it calls.");
                return;
            }

            var nb = _nb;
            bool diff = nb.IsDiff;

            if (nb.IsEmpty)
            {
                // Show just the centre node so the selection is visible, plus a note.
                double cw0 = Math.Clamp(W * 0.42, 180, 380), ch0 = 46;
                var only = new Rect(W / 2 - cw0 / 2, H / 2 - ch0 / 2, cw0, ch0);
                DrawCenter(dc, only, nb, dpi);
                var note = Text(diff
                        ? "No caller/callee relationships recorded for this function in either trace."
                        : "No recorded calls involve this function yet — run a capture, then exercise the program.",
                    _face, 12, HintText, dpi, W - 40, false);
                dc.DrawText(note, new Point(W / 2 - note.WidthIncludingTrailingWhitespace / 2, only.Bottom + 14));
                return;
            }

            if (W < 240)
            {
                DrawCentredHint(dc, W, H, dpi, "Widen this panel to see the call graph.");
                return;
            }

            double pad = 18;
            // Keep nodes narrow enough that the three columns never overlap on a
            // narrow pane: clamp by a fraction of the width AND by a third of it.
            double nodeW = Math.Min(Math.Clamp(W * 0.27, 120, 280), (W - 2 * pad) / 3.1);
            double centerH = 44;
            double leftCx = pad + nodeW / 2;
            double rightCx = W - pad - nodeW / 2;
            double centerCx = W / 2;
            double centerCy = H / 2;

            long maxCount = 1;
            foreach (var c in nb.Callers) if (c.Count > maxCount) maxCount = c.Count;
            foreach (var c in nb.Callees) if (c.Count > maxCount) maxCount = c.Count;

            double bottomReserve = diff ? 22 : 0; // room for the diff legend
            var callerBoxes = LayoutColumn(nb.Callers.Count, leftCx, nodeW, pad, H - bottomReserve);
            var calleeBoxes = LayoutColumn(nb.Callees.Count, rightCx, nodeW, pad, H - bottomReserve);
            var centerRect = new Rect(centerCx - nodeW / 2, centerCy - centerH / 2, nodeW, centerH);

            // Edges first (drawn under the nodes). Each edge carries an arrowhead at
            // the *called* end, so direction is explicit: caller -> centre on the left,
            // centre -> callee on the right.
            for (int i = 0; i < nb.Callers.Count; i++)
            {
                var c = nb.Callers[i];
                var r = callerBoxes[i];
                var (pen, fill) = diff ? DiffEdge(c, maxCount) : (EdgePen(VisualTheme.LinkSource, c.Count, maxCount), CallerBrush);
                DrawConnector(dc,
                    new Point(r.Right, r.Top + r.Height / 2),
                    new Point(centerRect.Left, centerRect.Top + centerRect.Height / 2),
                    pen, fill);
            }
            for (int i = 0; i < nb.Callees.Count; i++)
            {
                var c = nb.Callees[i];
                var r = calleeBoxes[i];
                var (pen, fill) = diff ? DiffEdge(c, maxCount) : (EdgePen(VisualTheme.LinkDest, c.Count, maxCount), CalleeBrush);
                DrawConnector(dc,
                    new Point(centerRect.Right, centerRect.Top + centerRect.Height / 2),
                    new Point(r.Left, r.Top + r.Height / 2),
                    pen, fill);
            }

            // Nodes.
            for (int i = 0; i < nb.Callers.Count; i++)
            {
                var c = nb.Callers[i];
                var (accent, pen) = NodeStyle(c, diff, caller: true);
                DrawNode(dc, callerBoxes[i], c, accent, pen, dpi, diff);
            }
            for (int i = 0; i < nb.Callees.Count; i++)
            {
                var c = nb.Callees[i];
                var (accent, pen) = NodeStyle(c, diff, caller: false);
                DrawNode(dc, calleeBoxes[i], c, accent, pen, dpi, diff);
            }

            DrawCenter(dc, centerRect, nb, dpi);

            DrawCaption(dc, leftCx, pad - 2, "CALLERS", diff ? "who calls it · A→B" : "who calls it", CallerBrush, dpi, nb.Callers.Count == 0);
            DrawCaption(dc, rightCx, pad - 2, "CALLEES", diff ? "what it calls · A→B" : "what it calls", CalleeBrush, dpi, nb.Callees.Count == 0);

            if (diff) DrawDiffLegend(dc, W, H, dpi);
        }

        // Node accent + border colour. In diff mode it encodes the change (green/red/
        // grey); otherwise it's the caller-warm / callee-cool of the live butterfly.
        private static (Brush accent, Pen pen) NodeStyle(CallNeighbor c, bool diff, bool caller)
        {
            if (!diff) return caller ? (CallerBrush, CallerPen) : (CalleeBrush, CalleePen);
            return c.CountB > c.CountA ? (MoreBrush, MorePen)
                 : c.CountB < c.CountA ? (LessBrush, LessPen)
                                       : (SameBrush, SamePen);
        }

        private static (Pen pen, Brush fill) DiffEdge(CallNeighbor c, long max)
        {
            Color color = c.CountB > c.CountA ? MoreColor : c.CountB < c.CountA ? LessColor : SameColor;
            long weight = Math.Max(c.CountA, c.CountB);
            return (EdgePen(color, weight, max), color == MoreColor ? MoreBrush : color == LessColor ? LessBrush : SameBrush);
        }

        private static List<Rect> LayoutColumn(int n, double cx, double nodeW, double pad, double H)
        {
            var rects = new List<Rect>(n);
            if (n == 0) return rects;
            double top = pad + 30, bottom = H - pad;
            double slot = (bottom - top) / n;
            double h = Math.Clamp(slot - 6, 20, 34);
            for (int i = 0; i < n; i++)
            {
                double cy = top + slot * (i + 0.5);
                rects.Add(new Rect(cx - nodeW / 2, cy - h / 2, nodeW, h));
            }
            return rects;
        }

        private void DrawNode(DrawingContext dc, Rect rect, CallNeighbor c, Brush accent, Pen pen, double dpi, bool diff)
        {
            bool hot = c.Address == _hover && c.Address != 0;
            dc.DrawRoundedRectangle(NodeFill, hot ? HoverPen : pen, rect, 6, 6);

            string countStr = diff
                ? $"{c.CountA:N0}→{c.CountB:N0}"
                : "×" + c.Count.ToString("N0", CultureInfo.CurrentUICulture);
            var ftCount = Text(countStr, _mono, 11.5, accent, dpi, rect.Width - 16, false);
            double countW = ftCount.WidthIncludingTrailingWhitespace;

            var ftName = Text(c.Name, _faceSemi, 12.5, NodeText, dpi, rect.Width - 22 - countW, true);
            dc.DrawText(ftName, new Point(rect.Left + 10, rect.Top + (rect.Height - ftName.Height) / 2));
            dc.DrawText(ftCount, new Point(rect.Right - 10 - countW, rect.Top + (rect.Height - ftCount.Height) / 2));

            _hits.Add(new Hit(rect, c.Address));
        }

        private void DrawCenter(DrawingContext dc, Rect rect, CallNeighborhood nb, double dpi)
        {
            // In diff mode the centre's border encodes its own call-count change.
            Pen pen = nb.IsDiff
                ? (nb.CenterCountB > nb.CenterCountA ? MorePen : nb.CenterCountB < nb.CenterCountA ? LessPen : SamePen)
                : CenterPen;
            dc.DrawRoundedRectangle(NodeFill, pen, rect, 7, 7);

            var ftName = Text(nb.CenterName, _faceSemi, 13.5, CenterBrush, dpi, rect.Width - 20, true);
            dc.DrawText(ftName, new Point(rect.Left + 11, rect.Top + 6));

            string sub = nb.IsDiff
                ? $"called {nb.CenterCountA:N0}→{nb.CenterCountB:N0}"
                : $"called {nb.TotalIn:N0}×   ·   calls {nb.TotalOut:N0}×";
            var ftSub = Text(sub, _mono, 11, SubText, dpi, rect.Width - 20, false);
            dc.DrawText(ftSub, new Point(rect.Left + 11, rect.Bottom - ftSub.Height - 5));
        }

        private void DrawCaption(DrawingContext dc, double cx, double y, string caption, string sub, Brush brush, double dpi, bool dim)
        {
            var ft = Text(caption, _faceSemi, 10.5, dim ? HintText : brush, dpi, 240, false);
            dc.DrawText(ft, new Point(cx - ft.WidthIncludingTrailingWhitespace / 2, y));

            // A plain-English second line disambiguates caller vs callee at a glance.
            var fs = Text(sub, _face, 9.5, HintText, dpi, 240, false);
            dc.DrawText(fs, new Point(cx - fs.WidthIncludingTrailingWhitespace / 2, y + 14));
        }

        // A compact "more / fewer / unchanged" key along the bottom in diff mode.
        private void DrawDiffLegend(DrawingContext dc, double W, double H, double dpi)
        {
            double y = H - 18, sw = 11, gap = 5, itemGap = 16;
            (Brush b, string t)[] items =
            {
                (MoreBrush, "more / new"),
                (LessBrush, "fewer / removed"),
                (SameBrush, "unchanged"),
            };

            // Measure to centre the whole strip.
            var texts = new FormattedText[items.Length];
            double total = 0;
            for (int i = 0; i < items.Length; i++)
            {
                texts[i] = Text(items[i].t, _face, 10, SubText, dpi, 200, false);
                total += sw + gap + texts[i].WidthIncludingTrailingWhitespace + (i < items.Length - 1 ? itemGap : 0);
            }

            double x = Math.Max(8, W / 2 - total / 2);
            for (int i = 0; i < items.Length; i++)
            {
                dc.DrawRoundedRectangle(items[i].b, null, new Rect(x, y, sw, sw), 2, 2);
                x += sw + gap;
                dc.DrawText(texts[i], new Point(x, y - 2));
                x += texts[i].WidthIncludingTrailingWhitespace + itemGap;
            }
        }

        private void DrawCentredHint(DrawingContext dc, double W, double H, double dpi, string text)
        {
            double maxW = Math.Min(W - 40, 520);
            var ft = new FormattedText(text, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight,
                _face, 13, HintText, dpi)
            { TextAlignment = TextAlignment.Center, MaxTextWidth = Math.Max(40, maxW) };
            dc.DrawText(ft, new Point(W / 2 - ft.MaxTextWidth / 2, H / 2 - ft.Height / 2));
        }

        private static void DrawConnector(DrawingContext dc, Point a, Point b, Pen pen, Brush arrowFill)
        {
            double mx = (a.X + b.X) / 2;
            var g = new StreamGeometry();
            using (var c = g.Open())
            {
                c.BeginFigure(a, false, false);
                c.BezierTo(new Point(mx, a.Y), new Point(mx, b.Y), b, true, false);
            }
            g.Freeze();
            dc.DrawGeometry(null, pen, g);

            // Arrowhead at the called end (b), aligned to the curve's approach. The
            // Bézier flattens to horizontal at b (its last control point shares b's Y),
            // so the head points straight into the function being called.
            DrawArrowHead(dc, b, b - new Point(mx, b.Y), arrowFill, pen.Thickness);
        }

        // A small filled triangle floating just off <paramref name="tip"/> and pointing
        // along <paramref name="dir"/> — the explicit "who calls whom" cue on each edge.
        private static void DrawArrowHead(DrawingContext dc, Point tip, Vector dir, Brush fill, double weight)
        {
            double len = dir.Length;
            if (len < 1e-3) dir = new Vector(1, 0); else dir /= len;
            var normal = new Vector(-dir.Y, dir.X);

            double size = Math.Clamp(6 + weight, 7, 12);
            Point apex = tip - dir * 2;            // float ~2px off the node so it reads fully
            Point baseC = apex - dir * size;
            Point p1 = baseC + normal * (size * 0.5);
            Point p2 = baseC - normal * (size * 0.5);

            var g = new StreamGeometry();
            using (var c = g.Open())
            {
                c.BeginFigure(apex, true, true);
                c.LineTo(p1, true, false);
                c.LineTo(p2, true, false);
            }
            g.Freeze();
            dc.DrawGeometry(fill, null, g);
        }

        private static Pen EdgePen(Color color, long count, long max)
        {
            double t = 1.2 + 4.0 * (Math.Log2(count + 1) / Math.Log2(Math.Max(2, max) + 1));
            var p = new Pen(new SolidColorBrush(Color.FromArgb(0xCC, color.R, color.G, color.B)), t);
            p.Freeze();
            return p;
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
