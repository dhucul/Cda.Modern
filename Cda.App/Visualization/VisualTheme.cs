using System.Windows;
using System.Windows.Media;

namespace Cda.App.Visualization
{
    /// <summary>
    /// Central palette for the visualization, aligned with the app theme in
    /// App.xaml (deep slate background, slate-grey idle nodes, an amber active
    /// node, and warm-to-cool call links that read direction without the harsh
    /// pure red/yellow of the original DirectX renderer).
    /// Brushes/pens are frozen so they can be shared across threads and reused
    /// every frame without per-frame allocation.
    /// </summary>
    public static class VisualTheme
    {
        public static readonly Brush Background = Freeze(new SolidColorBrush(Color.FromRgb(0x0E, 0x11, 0x16)));
        public static readonly Brush IdleNode = Freeze(new SolidColorBrush(Color.FromRgb(0x4A, 0x54, 0x62)));
        public static readonly Brush ActiveNode = Freeze(new SolidColorBrush(Color.FromRgb(0xE0, 0xB3, 0x41)));
        public static readonly Brush ModuleLabel = Freeze(new SolidColorBrush(Color.FromRgb(0xAE, 0xB7, 0xC4)));

        // Warm source -> cool destination, so an edge still encodes call direction.
        public static readonly Color LinkSource = Color.FromRgb(0xCB, 0x6B, 0x52);
        public static readonly Color LinkDest = Color.FromRgb(0x4D, 0x8D, 0xF7);

        // Two-tone pens let us show call direction (source half warm, dest half
        // blue) without allocating a gradient brush per edge per frame.
        public static readonly Pen LinkSourcePen = Freeze(new Pen(new SolidColorBrush(LinkSource), 1.0));
        public static readonly Pen LinkDestPen = Freeze(new Pen(new SolidColorBrush(LinkDest), 1.0));

        public static readonly Pen ModuleBoxPen =
            Freeze(new Pen(new SolidColorBrush(Color.FromArgb(0x3A, 0xAE, 0xB7, 0xC4)), 1.0));

        public const double NodeSize = 4.0;        // DIPs
        public const double LabelFontSize = 11.0;  // DIPs

        private static T Freeze<T>(T f) where T : Freezable
        {
            if (f.CanFreeze) f.Freeze();
            return f;
        }
    }
}
