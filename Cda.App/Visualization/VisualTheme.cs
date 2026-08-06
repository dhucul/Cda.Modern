using System.Windows;
using System.Windows.Media;

namespace Cda.App.Visualization
{
    /// <summary>
    /// Central palette for the visualization, aligned with the Graphite Blue
    /// theme in App.xaml: the graph field is the exact window Background so the
    /// pane reads as part of the window rather than an embedded box, idle nodes
    /// sit on the theme's outline tone, and the active node stays amber — the
    /// one warm colour in the app, so "what is running" can never be confused
    /// with the blue selection/accent cues around it.
    /// Brushes/pens are frozen so they can be shared across threads and reused
    /// every frame without per-frame allocation.
    /// </summary>
    public static class VisualTheme
    {
        // Matches App.xaml "Background" (#1B1E24).
        public static readonly Brush Background = Freeze(new SolidColorBrush(Color.FromRgb(0x1B, 0x1E, 0x24)));
        // Matches App.xaml "OutlineStrong" (#454D5C) — idle nodes recede to the
        // same weight as the chrome's hairlines.
        public static readonly Brush IdleNode = Freeze(new SolidColorBrush(Color.FromRgb(0x45, 0x4D, 0x5C)));
        public static readonly Brush ActiveNode = Freeze(new SolidColorBrush(Color.FromRgb(0xF2, 0xD0, 0x8A)));
        public static readonly Brush ModuleLabel = Freeze(new SolidColorBrush(Color.FromRgb(0xA7, 0xB0, 0xBD)));

        // Warm source -> cool destination, so an edge still encodes call direction.
        // The destination half is the theme accent (#4C8DFF), so an edge landing
        // on a node matches the selection colour that node gets when focused.
        public static readonly Color LinkSource = Color.FromRgb(0xE0, 0x92, 0x6F);
        public static readonly Color LinkDest = Color.FromRgb(0x4C, 0x8D, 0xFF);

        // Two-tone pens let us show call direction (source half warm, dest half
        // blue) without allocating a gradient brush per edge per frame.
        public static readonly Pen LinkSourcePen = Freeze(new Pen(new SolidColorBrush(LinkSource), 1.0));
        public static readonly Pen LinkDestPen = Freeze(new Pen(new SolidColorBrush(LinkDest), 1.0));

        public static readonly Pen ModuleBoxPen =
            Freeze(new Pen(new SolidColorBrush(Color.FromArgb(0x3A, 0x8A, 0x95, 0xA9)), 1.0));

        public const double NodeSize = 4.0;        // DIPs
        public const double LabelFontSize = 11.0;  // DIPs

        private static T Freeze<T>(T f) where T : Freezable
        {
            if (f.CanFreeze) f.Freeze();
            return f;
        }
    }
}
