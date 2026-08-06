using System.Windows;
using System.Windows.Media;

namespace Cda.App
{
    /// <summary>
    /// The application's type stack, in one place. XAML reaches the same two
    /// families through the "UiFont" / "MonoFont" resources in App.xaml; the
    /// custom-drawn surfaces (hex, disassembly, call graph, timeline, diff
    /// chart) build their FormattedText from the Typefaces here, so a font
    /// change lands everywhere at once instead of in fifteen string literals.
    ///
    /// Choices, and why:
    ///
    ///  UI — "Segoe UI Variable Text". Windows 11's optically-sized UI face; the
    ///  Text optical size is drawn specifically for 12–18px body copy, so it
    ///  keeps larger apertures and looser spacing than plain Segoe UI at the
    ///  sizes this app actually uses. Falls back to Segoe UI on Windows 10, then
    ///  Tahoma on anything older — WPF walks the comma-separated list itself, so
    ///  the app never lands on a serif default.
    ///
    ///  Mono — "Cascadia Mono". Chosen over Cascadia Code deliberately: Code's
    ///  programming ligatures fuse character pairs, which is actively wrong for a
    ///  hex dump or a disassembly listing where every glyph is one byte or one
    ///  token. Cascadia's zero is slashed and its 1/l/I are clearly distinct —
    ///  the two properties that matter most when reading addresses. Falls back to
    ///  Consolas (every Windows install) and then Courier New.
    /// </summary>
    internal static class AppFonts
    {
        public const string UiStack = "Segoe UI Variable Text, Segoe UI, Tahoma";
        public const string UiDisplayStack = "Segoe UI Variable Display, Segoe UI, Tahoma";
        public const string MonoStack = "Cascadia Mono, Consolas, Courier New";

        public static readonly FontFamily Ui = new(UiStack);
        public static readonly FontFamily UiDisplay = new(UiDisplayStack);
        public static readonly FontFamily Mono = new(MonoStack);

        // Typefaces are immutable and shared: constructing one per render pass
        // costs a font-cache lookup on every frame of the graph and timeline.
        public static readonly Typeface UiRegular =
            new(Ui, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
        public static readonly Typeface UiSemiBold =
            new(Ui, FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal);
        public static readonly Typeface MonoRegular =
            new(Mono, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
        public static readonly Typeface MonoSemiBold =
            new(Mono, FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal);
    }
}
