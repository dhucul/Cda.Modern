using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Cda.App.UI
{
    /// <summary>
    /// The Help ▸ Help Contents window: a searchable, categorized reference to
    /// every toolbar command, option, tab, and shortcut in CDA. The content is
    /// built in code from a static outline (below) so it stays close to the
    /// toolbar tooltips it distills and is trivial to filter row-by-row. Non-modal
    /// and single-instance (MainWindow reuses one), themed from the app palette.
    /// </summary>
    public partial class HelpWindow : Window
    {
        // A single command/panel/shortcut entry: a name and what it does.
        private sealed record Item(string Name, string Desc);

        // A titled group of entries, optionally introduced by a blurb.
        private sealed record Section(string Title, string? Blurb, Item[] Items);

        // Filterable rows and their owning section header, so a filter can hide a
        // header once all of its rows are hidden.
        private readonly List<(FrameworkElement Row, string Hay)> _rows = new();
        private readonly List<(FrameworkElement Header, List<FrameworkElement> Rows)> _groups = new();
        private readonly Dictionary<string, FrameworkElement> _anchors = new(StringComparer.OrdinalIgnoreCase);

        public HelpWindow()
        {
            InitializeComponent();
            Version.Text = "CDA — Dynamic Analysis (modern preview)   ·   v" + AppVersion();
            BuildContent();
        }

        private static string AppVersion()
        {
            var v = Assembly.GetExecutingAssembly().GetName().Version;
            return v == null ? "0.0" : $"{v.Major}.{v.Minor}.{v.Build}";
        }

        /// <summary>Scroll the given section's header into view (matched by title, case-insensitively).</summary>
        public void ScrollToSection(string sectionTitle)
        {
            // Defer until layout has run, so BringIntoView has real coordinates.
            Dispatcher.BeginInvoke(new Action(() =>
            {
                foreach (var kv in _anchors)
                {
                    if (kv.Key.IndexOf(sectionTitle, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        kv.Value.BringIntoView();
                        return;
                    }
                }
            }), System.Windows.Threading.DispatcherPriority.Loaded);
        }

        // ------------------------------------------------------------------ content

        private static readonly Section[] Sections =
        {
            new("Getting started", null, new[]
            {
                new Item("Analyze a running app",
                    "Attach to process…, then Capture Windows API (or Detect dialog caller). Exercise the app; " +
                    "calls stream into the Calls tab with decoded arguments."),
                new Item("Analyze from startup",
                    "Use a Launch & capture… command so hooks are armed before the first instruction — the only " +
                    "way to catch calls the target makes while starting up (attaching after the fact misses them)."),
                new Item("Review offline",
                    "Save trace… to a .cdatrace file, then reopen it later with Open trace… — functions, graph, " +
                    "timeline, calls, and caller tree, with no live target needed."),
            }),

            new("Sources — bring in a target", null, new[]
            {
                new Item("Open module (PE)…",
                    "Statically load an EXE/DLL: lists its functions and shows its bytes. Does NOT run it."),
                new Item("Attach to process…",
                    "Attach to a running process (read-only) and discover its modules and call graph. The first " +
                    "step before the on-attach capture commands."),
                new Item("Load demo trace",
                    "Load a built-in sample trace to explore the UI with no target."),
            }),

            new("Launch & capture — instrument from startup",
                "These launch the target with the hooks already armed, so the startup call flow is captured from " +
                "the very first instruction.", new[]
            {
                new Item("Launch & capture…",
                    "Launch an EXE suspended, arm a broad set of its own functions before it runs, then resume. " +
                    "Click any function afterward to focus the trace on just it."),
                new Item("Launch & capture API…",
                    "Launch and hook the Windows API functions the target imports (kernel32/user32/ntdll/…) before " +
                    "its entry point. Ultra-hot primitives are skipped to avoid flooding."),
                new Item("Launch & capture imports…",
                    "Like Launch & capture API, but rewrites only the import-table (IAT) slots — never code — so it " +
                    "works on anti-tamper targets that checksum their own .text and self-terminate when patched."),
                new Item("Launch & capture exports…",
                    "Launch and hook the functions the target's OWN modules export (the EXE and its app DLLs, not the " +
                    "OS). The mirror of Launch & capture API: that hooks what it calls out to; this hooks what its " +
                    "own code exposes."),
                new Item("Launch & detect dialogs…",
                    "Launch and hook only the OS dialog-box functions, so a dialog raised during startup (a splash, " +
                    "nag, or error box) is caught and attributed to the app function that raised it. Results appear " +
                    "in the Dialogs tab, each with its caption — a MessageBox's text and, for a custom app dialog " +
                    "built from a resource template (DialogBoxParam / CreateDialogParam / MFC), the title read from " +
                    "the dialog template itself — plus the text the app writes into the dialog's controls at runtime " +
                    "(SetWindowText / SetDlgItemText), so a message shown on a label or edit is revealed too."),
                new Item("Capture DLL…",
                    "Launch a host and instrument a chosen DLL the instant it loads — capturing its DllMain and " +
                    "startup. Pick the DLL, then optionally a host EXE (Cancel = use rundll32)."),
                new Item("Follow children…",
                    "Launch an EXE and follow every process it spawns, instrumenting each at creation (frozen before " +
                    "its code runs). Per-process call counts stream into the diagnostics."),
                new Item("Launch .NET & capture…",
                    "Launch a managed (.NET) EXE and capture its managed method calls from startup. Framework " +
                    "methods (System.*/Microsoft.*) are skipped. Requires a same-bitness CDA build as the target."),
            }),

            new("Launch options", null, new[]
            {
                new Item("Disable ASLR",
                    "For the launch commands, start the target at a fixed base every run so captured addresses are " +
                    "reproducible and comparable across saved traces. Affects only apps CDA launches; nothing global."),
                new Item("Skip system",
                    "When following a process tree, don't instrument OS helper processes (those under \\Windows\\, " +
                    "e.g. conhost.exe); they're still followed and listed, just not hooked."),
                new Item("Auto-bisect crashes",
                    "If a Launch & capture crash can't be pinned to a single hook, binary-search the hooks " +
                    "(relaunching hidden and bounded) to isolate the culprit; its RVA is written to cda_hook_skip.txt."),
            }),

            new("Capture on an attached process",
                "Attach to a process first, then choose how to instrument it.", new[]
            {
                new Item("Start capture",
                    "Instrument ONLY the function selected on the left and record its live calls with decoded " +
                    "arguments."),
                new Item("Capture Windows API",
                    "Hook the Windows API functions the attached process imports and record every call — with " +
                    "arguments and decoded strings. Ultra-hot primitives are skipped; click one to trace it."),
                new Item("Detect dialog caller",
                    "Hook only the OS dialog-box functions (MessageBox, DialogBoxParam, TaskDialog, …). When the " +
                    "target pops a dialog, the Dialogs tab shows its caption and — the point — the app function that " +
                    "raised it, lit up in the list, graph, and call stack. The caption is a MessageBox's text, or for " +
                    "a resource/template-defined custom dialog the title parsed from its dialog template; the text the " +
                    "app writes into the dialog's controls at runtime (SetWindowText / SetDlgItemText) is captured " +
                    "too, so the message on a static/label/edit is revealed, each with the function that set it."),
                new Item("Capture imports (IAT)",
                    "Like Capture Windows API, but reroutes calls by overwriting import-address-table SLOTS (data) " +
                    "instead of patching code — so it captures anti-tamper targets that checksum their own .text."),
                new Item("Capture (hardware bp)",
                    "Trace the SELECTED function using a CPU debug register — writes NOTHING to target memory. " +
                    "x64 only, up to 4 addresses; attaches as a debugger (anti-debug targets may notice)."),
                new Item("Capture .NET (managed)",
                    "On the attached .NET process, discover its JIT-compiled app methods (via ClrMD) and hook their " +
                    "native entries. A background timer re-scans for methods that JIT later. Same-bitness CDA build " +
                    "required."),
                new Item("Auto-capture on select",
                    "When on, clicking a function in the list immediately starts tracing it — no Start button needed."),
                new Item("Capture returns",
                    "When on, a focused capture also records each call's RETURN value (RAX/EAX), shown in the Calls " +
                    "log's Return column. Integer returns only; set before starting a capture."),
            }),

            new("Capture control", null, new[]
            {
                new Item("Stop capture",
                    "Remove all hooks and detach, freezing the current trace for review."),
                new Item("Clear calls",
                    "Clear the recorded calls, counts, caller tree, and graph so far but KEEP capturing — the hooks " +
                    "stay installed. Use it to reset, then exercise one action to see only what that triggers."),
                new Item("Only new on left",
                    "Filter the function list (left) to functions that have calls — they appear live as they run. " +
                    "Uncheck to show the full function list."),
                new Item("Capture only (condition)",
                    "Record only calls matching space-separated clauses (all must match): argN==V / != / < / > / &V " +
                    "(V is 0x-hex or decimal); name~TEXT or name!~TEXT (callee name contains); str~TEXT or str!~TEXT " +
                    "(decoded string arg contains). Blank = record everything. Applies live during capture."),
            }),

            new("Trace I/O & review", null, new[]
            {
                new Item("Save trace…",
                    "Save the recorded calls — with arguments, decoded strings, and stack snapshots — to a " +
                    ".cdatrace file you can reopen and review later."),
                new Item("Open trace…",
                    "Open a saved .cdatrace file and review it offline: functions, call graph, timeline, calls log, " +
                    "and caller tree (no live target needed)."),
                new Item("Export CSV…",
                    "Export the recorded calls to a spreadsheet-friendly CSV (one row per call). One-way — use " +
                    "Save trace… for a file you can reopen in CDA."),
                new Item("Compare trace…",
                    "Compare two traces (A vs B): a per-function call-count diff (which functions ran only in one " +
                    "run, or a different number of times) and a recolored butterfly graph. Double-click a row to jump."),
                new Item("Copy results",
                    "Copy the captured calls and current diagnostic state to the clipboard as text."),
            }),

            new("View & diagnostics", null, new[]
            {
                new Item("Fit graph",
                    "Zoom and center the call graph to fit the window."),
                new Item("Self-test",
                    "In-process validation (no target) of the inline-hook codegen and the capture stub + ring " +
                    "buffer. A failure here means the codegen needs fixing before trusting a live capture."),
            }),

            new("Panels & tabs", null, new[]
            {
                new Item("Function list (left)",
                    "Every discovered function; click one to focus the trace, graph, hex, and disassembly on it. " +
                    "With Auto-capture on, clicking also starts tracing it."),
                new Item("Call graph",
                    "A butterfly graph around the focused function; click a node to refocus the trace on it."),
                new Item("Timeline (bottom)",
                    "Playback bar over the capture — click to scrub, ←/→ to step, right-drag to select a range."),
                new Item("Calls",
                    "One row per recorded call: time, caller, callee, decoded arguments (and return value, if " +
                    "Capture returns is on)."),
                new Item("Called by",
                    "The caller tree — which functions called the selected one, and how often."),
                new Item("Call stack",
                    "The captured stack snapshot for the selected call."),
                new Item("Dialogs",
                    "One row per dialog the target raised, with its caption and the app function that created it " +
                    "(from Detect dialog caller / Launch & detect dialogs…). Click a row to jump to that caller."),
                new Item("Memory",
                    "A hex view of the selected function's or module's bytes."),
                new Item("Disassembly",
                    "Disassembly of the selected function; for a managed (.NET) selection, IL plus decompiled C#."),
                new Item("Strings",
                    "Strings extracted from the target (scanned lazily the first time you open the tab)."),
            }),

            new("Keyboard & mouse", null, new[]
            {
                new Item("F1", "Open this help."),
                new Item("Click a graph node", "Focus the trace on that function."),
                new Item("Click the timeline", "Scrub playback to that point."),
                new Item("← / →", "Step the timeline (hold Ctrl for a bigger step)."),
                new Item("Right-drag the timeline", "Select a time range."),
                new Item("Double-click a compare row", "Jump to that function."),
            }),
        };

        // ------------------------------------------------------------------ rendering

        private void BuildContent()
        {
            var accent    = Brush("Accent",        Colors.SteelBlue);
            var primary   = Brush("TextPrimary",   Colors.White);
            var secondary = Brush("TextSecondary", Colors.LightGray);

            bool first = true;
            foreach (var section in Sections)
            {
                var headerPanel = new StackPanel { Margin = new Thickness(0, first ? 0 : 22, 0, 8) };
                first = false;

                headerPanel.Children.Add(new TextBlock
                {
                    Text = section.Title,
                    FontSize = 15,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = accent,
                });
                if (!string.IsNullOrEmpty(section.Blurb))
                {
                    headerPanel.Children.Add(new TextBlock
                    {
                        Text = section.Blurb,
                        Foreground = secondary,
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(0, 3, 0, 0),
                    });
                }
                // Hairline under the section title.
                headerPanel.Children.Add(new Border
                {
                    Height = 1,
                    Background = Brush("Outline", Colors.DimGray),
                    Margin = new Thickness(0, 8, 0, 0),
                });

                Body.Children.Add(headerPanel);
                _anchors[section.Title] = headerPanel;

                var rowElems = new List<FrameworkElement>();
                foreach (var item in section.Items)
                {
                    var grid = new Grid { Margin = new Thickness(0, 6, 0, 0) };
                    grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(240) });
                    grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

                    var name = new TextBlock
                    {
                        Text = item.Name,
                        Foreground = primary,
                        FontWeight = FontWeights.SemiBold,
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(0, 0, 12, 0),
                        VerticalAlignment = VerticalAlignment.Top,
                    };
                    Grid.SetColumn(name, 0);

                    var desc = new TextBlock
                    {
                        Text = item.Desc,
                        Foreground = secondary,
                        TextWrapping = TextWrapping.Wrap,
                        VerticalAlignment = VerticalAlignment.Top,
                    };
                    Grid.SetColumn(desc, 1);

                    grid.Children.Add(name);
                    grid.Children.Add(desc);
                    Body.Children.Add(grid);

                    rowElems.Add(grid);
                    _rows.Add((grid, (item.Name + " " + item.Desc).ToLowerInvariant()));
                }

                _groups.Add((headerPanel, rowElems));
            }
        }

        private SolidColorBrush Brush(string key, Color fallback) =>
            TryFindResource(key) as SolidColorBrush ?? new SolidColorBrush(fallback);

        // ------------------------------------------------------------------ filter

        private void OnFilter(object sender, TextChangedEventArgs e)
        {
            string q = Filter.Text.Trim().ToLowerInvariant();

            foreach (var (row, hay) in _rows)
                row.Visibility = q.Length == 0 || hay.Contains(q)
                    ? Visibility.Visible : Visibility.Collapsed;

            // Hide a section header once every one of its rows is filtered out.
            foreach (var (header, rows) in _groups)
                header.Visibility = rows.Any(r => r.Visibility == Visibility.Visible)
                    ? Visibility.Visible : Visibility.Collapsed;
        }

        private void OnClose(object sender, RoutedEventArgs e) => Close();

        // ------------------------------------------------------------------ About

        /// <summary>
        /// A small, theme-matched About dialog (built in code so it needs no extra
        /// XAML file and picks up the app palette).
        /// </summary>
        public static void ShowAbout(Window owner)
        {
            SolidColorBrush B(string key, Color fb) =>
                (Application.Current?.TryFindResource(key) as SolidColorBrush) ?? new SolidColorBrush(fb);

            var bg        = B("Background",    Colors.Black);
            var surface   = B("Surface",       Colors.DimGray);
            var accent    = B("Accent",        Colors.SteelBlue);
            var primary   = B("TextPrimary",   Colors.White);
            var secondary = B("TextSecondary", Colors.LightGray);
            var muted     = B("TextMuted",     Colors.Gray);

            var stack = new StackPanel { Margin = new Thickness(22) };
            stack.Children.Add(new TextBlock
            {
                Text = "CDA — Dynamic Analysis",
                FontSize = 18, FontWeight = FontWeights.SemiBold, Foreground = accent,
            });
            stack.Children.Add(new TextBlock
            {
                Text = "modern preview · v" + AppVersion(),
                Foreground = muted, Margin = new Thickness(0, 2, 0, 0),
            });
            stack.Children.Add(new TextBlock
            {
                Text = "A modern C#/.NET + WPF rebuild of the inline-hook dynamic-analysis tool " +
                       "(Iced-based x86/x64 disassembly, with a managed .NET path). It records the " +
                       "function calls a program makes — live or from the first instruction at startup — " +
                       "and attributes each one to the code that made it.",
                Foreground = secondary, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 14, 0, 0), MaxWidth = 380,
            });

            var close = new Button { Content = "Close", Padding = new Thickness(18, 5, 18, 5),
                HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 18, 0, 0) };
            stack.Children.Add(close);

            var win = new Window
            {
                Title = "About CDA",
                Owner = owner,
                Width = 440,
                SizeToContent = SizeToContent.Height,
                ResizeMode = ResizeMode.NoResize,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Background = bg,
                Content = new Border { Background = surface, Child = stack },
            };
            close.Click += (_, _) => win.Close();
            win.ShowDialog();
        }
    }
}
