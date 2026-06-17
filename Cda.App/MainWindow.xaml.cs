using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Cda.App.Demo;
using Cda.App.Model;
using Cda.App.UI;
using Cda.App.Visualization;
using Cda.Core.Cpu;
using Cda.Core.Engine;
using Cda.Core.Memory;
using Cda.Core.Model;
using Cda.Core.Pe;
using Cda.Core.Process;

namespace Cda.App
{
    public partial class MainWindow : Window
    {
        private readonly CallGraphModel _model = new();
        private ModuleMap? _moduleMap;
        private PeImage? _currentPe;
        private LiveSession? _session;
        private TraceDataset? _liveDataset;
        private CaptureSession? _capture;
        private readonly List<CallRecord> _captured = new();
        private CaptureCondition? _captureCondition; // "Capture only" condition (null = keep every call)
        private DispatcherTimer? _pollTimer;
        private bool _is64 = true;
        private ulong _selectedFunctionAddr;
        private int _maxCursorSeen;  // diagnostic: high-water mark of in-target buffer writes
        private bool _captureBursting; // true while polls are draining a heavy startup flood
        private bool _polling;         // true while a background Poll() is in flight (re-entrancy guard)
        private int _captureClearGen;  // bumped by "Clear calls"; a poll batch decoded across a clear is dropped
        private CaptureChainResolver? _chainResolver;  // worker-thread caller-chain resolver for live polls
        private LiveSession? _chainResolverSession;    // session the resolver was built for (rebuild on change)
        private ModuleMap? _chainResolverMap;          // module map the resolver was built for
        private readonly HashSet<ulong> _autoUnhooked = new(); // callees auto-removed mid-capture as runaways
        private readonly List<string> _diag = new(); // step-by-step log, included in Copy results
        private DebugLoadCapture? _dllCapture; // active DLL-at-load capture, if any
        private ChildFollowCapture? _childFollow; // active child-process-follow capture, if any
        private HwBreakpointCapture? _hwbp; // active hardware-breakpoint (debug-register) capture, if any
        private ulong _captureFocus; // function the live trace is focused on (0 = broad)
        private MappedFileMemorySource? _fileMap; // memory-mapped backing for an opened file's hex view
        private bool _offlineTrace; // a saved trace loaded for review (no live session/target)
        private UI.CompareWindow? _compareWindow; // the open trace-comparison window, if any
        private Model.GraphDiff? _graphDiff;       // diff overlay driving the butterfly while comparing

        // --- Strings tab (deferred) -----------------------------------------
        // The Strings tab is scanned lazily — only when the user first opens that
        // tab — so a launch/attach/open never pays the disassembly + memory-read cost
        // unless the strings are actually wanted.
        private Func<List<ExtractedString>>? _pendingStringScan;
        private TraceDataset? _pendingStringScanDs;
        private int _stringScanGen; // bumps on every target change; invalidates an in-flight scan

        // --- startup-trace crash watch --------------------------------------
        // The "Launch & capture" path runs the target under a side debugger
        // (DebugCrashWatch) so a fault a spliced hook causes is caught live, with the
        // faulting address/registers and the hook it's pinned to — instead of dying
        // with only an opaque exit code. It reports the fault and stops; it does NOT
        // relaunch the target.
        private DebugCrashWatch? _debugWatch;
        private string? _startupPath;           // the EXE under a startup trace
        private string? _startupName;
        private ulong[]? _startupSortedEntries;  // discovered entry points (sorted) for fault attribution
        private HashSet<ulong>? _startupHookedSet; // the armed hook targets, for fault attribution
        private readonly Dictionary<ulong, bool> _startupRetCache = new(); // stack word -> looks like a return address
        private int _startupGeneration;          // monotonic token: a superseded post-start coroutine bails (guards rapid re-launches)
        private ulong _startupImageBase;         // main image base this attempt, to turn a culprit address into a stable RVA
        private bool _disableAslr;               // launch the target with ASLR forced off (set from the toolbar at launch time)
        // Originals we wrote a fixed-base (ASLR-stripped) copy next to this session, so
        // those copies can be best-effort swept on close (the ones whose target exited).
        private readonly HashSet<string> _fixedBaseOriginals = new(StringComparer.OrdinalIgnoreCase);

        // --- tamed auto-bisection (opt-in: "Auto-bisect crashes") ------------
        // An unattributable startup crash (a deferred culprit that can't be pinned at
        // fault time) kicks off a binary search over the armed set: each test arms a
        // subset and relaunches the target HIDDEN, using "ran BisectSurviveMs with no
        // fault" as the PASSED signal. It isolates ONE culprit, appends its RVA to the
        // skip-list (cda_hook_skip.txt), and stops — the user's manual re-launches drive
        // the rest. Only the hidden test runs relaunch; bounded and Stop-cancellable.
        private bool _startupActive;             // true while THIS capture is a launch-startup trace (gates the search)
        private bool _faultSeenThisAttempt;      // a fatal fault was caught this attempt
        private bool _crashAppendedThisAttempt;  // this attempt's crash was pinned + written to the skip-list
        private bool _startupStop;               // user hit Stop: abort any pending relaunch before it resumes a target
        private bool _bisecting;                 // a binary search is in progress (its test runs launch hidden)
        private ulong[] _bisectPool = Array.Empty<ulong>(); // ordered suspect hooks
        private int _bisectLo, _bisectHi;        // [lo,hi): window still assumed to crash
        private int _bisectMid;                  // split point of the in-flight test (arming [lo,mid))
        private HashSet<ulong>? _bisectArmOnly;  // when set, the attempt arms ONLY these addresses
        private long _bisectDeadline;            // TickCount64 survive deadline for the in-flight hidden test (0 = none)
        private int _bisectRelaunches;           // hidden test relaunches this search (bounded)
        private const int BisectSurviveMs = 8000;   // a hidden test that runs this long with no fault is clean
        private const int MaxBisectRelaunches = 40; // hard ceiling on hidden test relaunches per search

        // --- child-follow multi-target state (Stage 3) -----------------------
        // While "Follow children" runs, each instrumented process becomes a target
        // here, keeping its own dataset + (bounded) captured records. Selecting a
        // target in the toolbar drives the single-target views from its data; the
        // others keep recording in the background. A child target has no live
        // session (so no hex view, and caller frames come from stack snapshots like
        // an offline trace) — everything driven by the recorded calls still works.
        private sealed class ChildTarget
        {
            public int Pid;
            public bool Is64;
            public string Image = "";
            public TraceDataset Dataset = null!;
            public ModuleMap ModuleMap = null!;
            public readonly List<CallRecord> Records = new(); // captured calls (bounded)
            public long TotalCalls;                            // cumulative, incl. trimmed
            public bool Exited;
            public ChildTargetItem Item = null!;
        }

        // Selector row; Display updates live (call count / exited) without losing
        // the ComboBox selection.
        private sealed class ChildTargetItem : System.ComponentModel.INotifyPropertyChanged
        {
            public int Pid;
            private string _display = "";
            public string Display
            {
                get => _display;
                set { _display = value; PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(Display))); }
            }
            public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
        }

        private readonly Dictionary<int, ChildTarget> _childTargets = new();
        private readonly System.Collections.ObjectModel.ObservableCollection<ChildTargetItem> _childItems = new();
        private int _childSelectedPid = -1; // currently displayed child target (-1 = none)
        private bool _childView;            // active views are showing a child target
        private const int ChildKeepLast = 50000; // per-target captured-record cap (bounds memory)

        // Lazy callee-name index (address -> real exported/API name). Feeds the
        // Calls log's labels and Win32 signature lookup; rebuilt when the active
        // dataset changes, mirroring the caller-index pattern.
        private TraceDataset? _nameIndexFor;
        private readonly Dictionary<ulong, string> _calleeNames = new();

        // "Called by" panel state. _callersFor is the function whose callers we are
        // showing. The caller relationships are kept as a global reverse-edge map
        // (callee -> {caller -> count}) folded from every record's stack chain, so
        // the tree can recurse past the depth of any single snapshot by composing
        // edges across records. _calleeTotals is the per-function call count for the
        // header. _idxAddr / _idxName floor a return address to its function.
        private ulong _callersFor;
        private readonly Dictionary<ulong, Dictionary<ulong, long>> _callerEdges = new();
        private readonly Dictionary<ulong, long> _calleeTotals = new();
        private readonly Dictionary<ulong, string> _fnNames = new();
        private ulong[] _idxAddr = Array.Empty<ulong>();
        private string[] _idxName = Array.Empty<string>();
        private TraceDataset? _callerIndexFor; // dataset the function index was built for

        private const int MaxCallerDepth = 12;   // how far the "Called by" tree recurses
        private const int MaxCallerNodes = 3000;  // total nodes built per tree (bound)

        // Broad "Capture Windows API" trace active: a click then inspects callers
        // (the follow-up) rather than refocusing the whole trace onto one API.
        private bool _apiCaptureMode;
        private string? _winDir; // cached Windows directory, for app/system classification
        private readonly Dictionary<ulong, bool> _appModuleCache = new(); // module base -> is app code
        private readonly Dictionary<ulong, bool> _retAddrCache = new();   // code addr -> looks like a return address

        // Exact x64 .pdata unwinder for the current live session (null when x86,
        // offline, or no session). Rebuilt when the session changes.
        private StackUnwinder? _unwinder;
        private LiveSession? _unwinderFor;

        // Below this many functions found before the program runs, we treat the
        // target as packed/compressed (only its unpacker stub is visible yet) and
        // do NOT hook before run — hooking the unpacker corrupts it, and the
        // program never launches. We trace the real code after startup instead.
        //
        // Tuning: a packer's unpacker stub is tiny (Rufus showed 8 functions; most
        // are well under 16). A normal small program usually exposes more. 16 is a
        // deliberately low bar so ordinary small binaries still get a true pre-run
        // startup trace; if one is misjudged as packed the only cost is missing the
        // first moments of startup — the post-start broad trace still captures it.
        private const int MinPreRunFunctions = 16;

        // Broad/startup trace sizing. We instrument up to StartupTraceFunctions and
        // draw them from a larger candidate pool (extra candidates cover sites the
        // engine has to skip). The ring buffer holds StartupBufferRecords slots —
        // large enough that this many hooks can't lap the reader between polls.
        private const int StartupTraceFunctions = 128;
        private const int StartupCandidatePool = 256;
        private const int StartupBufferRecords = 65536;

        // A poll that decodes at least this many records is treated as a heavy
        // startup flood: while batches stay this large the window is briefly busy,
        // so we show a wait cursor + "catching up" status, then a "ready" status
        // once the batches subside. Below this, ticks stay snappy.
        private const int CaptureBurstBatch = 1500;

        // Adaptive auto-unhook of a "runaway" function — one hooked primitive called
        // so often it floods the ring and forces record loss, drowning out the rest
        // of the trace. When a broad capture's poll batch is heavy and a single
        // callee both dominates it and has amassed this many cumulative calls, we
        // remove just that one hook so everything else keeps recording cleanly.
        private const int RunawayBatchMin = 2000;       // only evaluate the dominance path on heavy batches
        private const double RunawayBatchShare = 0.35;  // one callee ≥ this share of the batch
        private const int RunawayMinCalls = 20000;      // …and at least this many cumulative calls
        // Hard cumulative ceiling: any hooked callee past this many total calls is
        // unhooked no matter how its calls are spread over time — the backstop for a
        // DIFFUSE runaway (steady high volume that never dominates a single poll
        // batch, so the per-batch dominance path above never trips). Set above
        // RunawayMinCalls so a bursty runaway is still caught earlier by dominance.
        private const int RunawayCeilingCalls = 50000;

        // Upper bound on Windows API entry points hooked by "Capture Windows API".
        // Most programs import far fewer; if a target exceeds this we hook the
        // first this-many (alphabetical) and say so. Hooking happens with the
        // target frozen, so this also bounds how long it stays suspended.
        private const int ApiTraceFunctions = 512;

        // A module larger than this is opened as a memory-mapped hex view only: we
        // skip reading the whole file into a managed buffer and skip the static
        // call-site scan, both of which scale with file size (and cannot fit at all
        // in a 32-bit process). The limit is lower for the 32-bit build, where the
        // 2 GB user address space is the binding constraint.
        private static long MaxScanFileBytes =>
            Environment.Is64BitProcess ? 512L * 1024 * 1024 : 256L * 1024 * 1024;

        private void Diag(string msg)
        {
            _diag.Add(msg);
            StatusText.Text = msg;
        }

        public MainWindow()
        {
            InitializeComponent();
            PlayBar.WindowChanged += OnWindowChanged;
            FunctionList.FunctionSelected += OnFunctionSelected;
            FunctionList.CountFilterChanged += OnFunctionFilterChanged;
            GraphView.NeighborSelected += OnGraphNeighborSelected;
            CallList.CallSelected += (_, rec) => { Hex.GoTo(rec.Destination); ShowCallStack(rec); };
            // Reverse of the function-click → call sync: when the user clicks a row in
            // the Calls log, follow that call's callee in the function list and the graph.
            // Scoped to CallClicked (a deliberate row pick) rather than the broader
            // CallSelected, so it does NOT fire on the programmatic selections — the
            // timeline scrub (which by design must not move the function selection or the
            // graph) or the function-click round-trip. Both are the silent re-centre forms
            // (SelectByAddress doesn't raise FunctionSelected; SetSelected doesn't raise
            // NeighborSelected), so there's no feedback loop and no live-trace refocus — a
            // call-click navigates the views without disturbing a running capture's focus.
            CallList.CallClicked += (_, rec) =>
            {
                FunctionList.SelectByAddress(rec.Destination); // highlight in the function list
                GraphView.SetSelected(rec.Destination);        // re-centre the butterfly graph
            };
            CallList.SetNameResolver(ResolveCalleeName);
            Callers.CallerSelected += (_, addr) => OnCallerSelected(addr);
            CallStack.FrameSelected += (_, addr) => OnCallerSelected(addr);
            StringsPanel.FunctionActivated += OnStringFunctionActivated;
            StringsPanel.Shown += (_, _) => RunStringScan(); // lazy: scan when the tab is opened
            ChildTargetBox.ItemsSource = _childItems;
            Loaded += (_, _) =>
            {
                UpdateDpiText();
                LoadDemo();
            };
        }

        // --- demo trace ------------------------------------------------------

        private void OnLoadDemo(object sender, RoutedEventArgs e) => LoadDemo();

        private void OnFit(object sender, RoutedEventArgs e) => GraphView.FitToContent();

        private void OnSelfTest(object sender, RoutedEventArgs e)
        {
            // Runs in-process with no target: validates the inline-hook codegen
            // (patch sizing, stolen-byte relocation, jump encoding) and the capture
            // stub + ring buffer (one record per call, then chains to the
            // trampoline) for the current build's bitness — the byte-exact pieces
            // everything else depends on. Run this after any codegen change.
            string hook = HookSelfTest.Run();
            string capture = CaptureStubSelfTest.Run();
            StatusText.Text = $"Self-test · hook: {hook} · capture: {capture}";
        }

        private void LoadDemo()
        {
            TraceDataset data = DemoDataSource.Generate();
            SetCallersTarget(0);
            _offlineTrace = false;
            _childView = false;
            _is64 = true;
            _currentPe = null;
            _moduleMap = new ModuleMap(data.Modules);

            _model.Load(data);
            GraphView.SetModel(_model);
            PlayBar.SetData(data);
            FunctionList.LoadFromDataset(data);
            DisposeFileMap();
            Hex.SetSource(null);
            ClearStringsTab(); // the demo has no backing image to mine strings from

            StatusText.Text =
                $"Demo trace · {data.Modules.Count} modules · {data.Functions.Count} functions · {data.Records.Count} calls over {data.TimeEnd:0.0}s · (open a PE to populate the hex view)";
        }

        // --- open a real PE module (exercises the engine) --------------------

        private async void OnOpenModule(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Open a PE module",
                Filter = "Executables and libraries (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*",
            };
            if (dlg.ShowDialog(this) != true) return;

            // A file view is a different mode from live capture; stop capturing
            // first so the poll timer doesn't fight the file's data.
            StopDllCapture();
            StopChildFollow();
            StopCaptureQuietly(); // defers disposal if a background poll is in flight

            // A static file view doesn't use the live session; release it so we
            // don't hold the target's process handle open while browsing a file,
            // and stop the hex view from reading a process we're about to drop.
            _session?.Dispose();
            _session = null;
            Hex.SetSource(null);
            SetCallersTarget(0);
            _offlineTrace = false;
            _childView = false;
            ClearStringsTab(); // armed below for a normal-size PE; stays empty for an oversized one

            string path = dlg.FileName;
            string name = Path.GetFileName(path);

            long length;
            try { length = new FileInfo(path).Length; }
            catch (Exception ex) { StatusText.Text = $"Couldn't open {name}: {ex.Message}"; return; }

            StatusText.Text = $"Opening {name} ({FormatSize(length)})…";

            // Very large module: don't read it all into a managed buffer (it can't
            // fit in a 32-bit process, and is wasteful in a 64-bit one). Memory-map it
            // so the hex view is browsable with pages loaded on demand, and still
            // discover functions by streaming each executable section through a mapped
            // view — never the whole file, and with no byte cap, so a big .text is
            // covered end-to-end (bounded only by maxEdges). This is the same static
            // discovery the normal path and "Launch & capture" run; only the byte source
            // differs, so a large EXE populates the function list and graph instead of
            // opening empty. The full-file Strings scan stays skipped (it would re-read
            // the whole file); strings come from launch/attach.
            if (length > MaxScanFileBytes)
            {
                try
                {
                    var pe = await Task.Run(() => ProbePeHeader(path));
                    bool is64 = pe.Is64Bit;

                    // Discover on a worker, reading through a short-lived mapped source
                    // owned entirely by this Task (disposed here). _fileMap is touched
                    // only on the UI thread — as everywhere else in this class — so a
                    // re-entrant Open/Attach that disposes _fileMap can't race this read.
                    var (funcs, edges) = await Task.Run(() =>
                    {
                        var arch = CpuArchitectures.For(is64);
                        var fs = new List<TracedFunction>();
                        var es = new List<(ulong Site, ulong Target)>();
                        using var scanSrc = new MappedFileMemorySource(path, is64);
                        CallSiteScanner.ScanFileImage(scanSrc, pe, arch, fs, es, maxEdges: 20000);
                        return (fs, es);
                    });

                    var module = new ModuleInfo(name, pe.PreferredImageBase, pe.SizeOfImage, path);
                    _currentPe = pe;
                    _is64 = is64;
                    _liveDataset = null;
                    _selectedFunctionAddr = 0;
                    _moduleMap = new ModuleMap(new[] { module });

                    var ds = new TraceDataset { TimeStart = 0, TimeEnd = 1 };
                    ds.Modules.Add(module);
                    ds.Functions.AddRange(funcs);
                    int en = Math.Max(1, edges.Count);
                    for (int i = 0; i < edges.Count; i++)
                        ds.Records.Add(new CallRecord((double)i / en, edges[i].Site, edges[i].Target));

                    // The hex view's persistent map: created on the UI thread, after the
                    // worker is done, as the normal path does.
                    DisposeFileMap();
                    _fileMap = new MappedFileMemorySource(path, is64);

                    _model.Load(ds);
                    GraphView.SetModel(_model);
                    PlayBar.SetData(ds);
                    FunctionList.LoadFromDataset(ds);
                    Hex.SetSource(_fileMap, 0);

                    StatusText.Text =
                        $"{name} · {FormatSize(length)} · {(is64 ? "PE32+ (x64)" : "PE32 (x86)")} · base 0x{pe.PreferredImageBase:X} · " +
                        $"{ds.Functions.Count} functions (large file — hex memory-mapped; full read + strings skipped, launch/attach for strings)";
                }
                catch (Exception ex)
                {
                    StatusText.Text = $"Couldn't open {name}: {ex.Message}";
                }
                return;
            }

            try
            {
                // Parsing + a full static disassembly can take a moment on a large
                // module, so do it off the UI thread — otherwise the window appears
                // frozen and looks like nothing happened.
                var r = await Task.Run(() => OpenModuleCore(path, name));

                _currentPe = r.Pe;
                _is64 = r.Pe.Is64Bit;
                _moduleMap = new ModuleMap(new[] { r.Module });

                _liveDataset = null; // static file view, not a live session
                _model.Load(r.Dataset);
                GraphView.SetModel(_model);
                PlayBar.SetData(r.Dataset);
                FunctionList.LoadFromDataset(r.Dataset);

                // Strings tab: arm a DEFERRED scan — re-read + scan the file only when
                // the user opens the Strings tab, so opening a module stays quick.
                string capturedPath = path;
                var capturedDs = r.Dataset;
                ArmStringScan(() =>
                {
                    byte[] b = File.ReadAllBytes(capturedPath);
                    var p = PeImage.FromFile(b);
                    return StringScanner.Scan(b, p, capturedDs.Functions);
                }, r.Dataset);

                // Hex reads through a memory-mapped view rather than a pinned copy,
                // so the parse/scan buffer is released as soon as this returns and
                // the file is never held on the managed heap.
                DisposeFileMap();
                _fileMap = new MappedFileMemorySource(path, r.Pe.Is64Bit);
                Hex.SetSource(_fileMap, 0);

                StatusText.Text =
                    $"{name} · {FormatSize(length)} · {(r.Pe.Is64Bit ? "PE32+ (x64)" : "PE32 (x86)")} · base 0x{r.Pe.PreferredImageBase:X} · " +
                    $"{r.Dataset.Functions.Count} functions ({r.ExportCount} exports) · {r.Imports} imports · {r.Pe.Sections.Count} sections";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Couldn't open {name}: {ex.Message}";
            }
        }

        // Runs on a background thread: read + parse + statically scan the file,
        // returning everything the UI needs. Must not touch UI elements.
        private static (PeImage Pe, ModuleInfo Module, TraceDataset Dataset, int ExportCount, int Imports)
            OpenModuleCore(string path, string name)
        {
            // Read once into a right-sized buffer (peak ~1x the file size, versus
            // the ~2-3x of a growing MemoryStream that ToArray then copies again).
            // Full sharing so a file currently mapped/in use by another process
            // (a loaded DLL, a running EXE) can still be read. This buffer backs
            // only the parse + static scan and is freed when we return; the hex
            // view reads from a memory-mapped view instead, so nothing this large
            // stays pinned on the managed heap.
            byte[] bytes;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                       FileShare.ReadWrite | FileShare.Delete))
            {
                long len = fs.Length;
                bytes = new byte[len];
                int total = 0;
                while (total < len)
                {
                    int n = fs.Read(bytes, total, (int)Math.Min(len - total, int.MaxValue));
                    if (n == 0) break;
                    total += n;
                }
            }

            var pe = PeImage.FromFile(bytes);
            var module = new ModuleInfo(name, pe.PreferredImageBase, pe.SizeOfImage, path);

            // Discover functions two ways: the export table (named) and a static
            // scan of the code sections for direct-call targets. An EXE typically
            // exports nothing, so the scan is what populates the list for it.
            var arch = CpuArchitectures.For(pe.Is64Bit);
            var discovered = new List<TracedFunction>();
            var edges = new List<(ulong Site, ulong Target)>();
            CallSiteScanner.ScanFileImage(bytes, pe, arch, discovered, edges, maxEdges: 8000);

            var byAddr = new Dictionary<ulong, TracedFunction>();
            foreach (var f in discovered) byAddr[f.Address] = f;

            int exportCount = 0;
            foreach (var ex in pe.ReadExports())
            {
                if (ex.IsForwarder) continue;
                exportCount++;
                ulong va = pe.RvaToVa(ex.Rva);
                string exName = ex.Name ?? $"Ordinal_{ex.Ordinal}";
                if (byAddr.TryGetValue(va, out var existing)) existing.Name = exName;
                else byAddr[va] = new TracedFunction(va, pe.PreferredImageBase, exName);
            }

            var ds = new TraceDataset { TimeStart = 0, TimeEnd = 1 };
            ds.Modules.Add(module);
            ds.Functions.AddRange(byAddr.Values);
            int en = Math.Max(1, edges.Count);
            for (int i = 0; i < edges.Count; i++)
                ds.Records.Add(new CallRecord((double)i / en, edges[i].Site, edges[i].Target));

            int imports = pe.ReadImports().Count;
            return (pe, module, ds, exportCount, imports);
        }

        // Cheap PE header parse from just a prefix — used for very large files we
        // deliberately don't read or scan in full. A small prefix holds the DOS
        // header, PE header, optional header, and section table for any real binary,
        // which is everything the static section scan needs (bitness, preferred base,
        // SizeOfImage, and each section's raw offset/size). The returned PeImage is
        // header-only: its section *body* bytes are NOT in the buffer, so callers must
        // not read exports/imports/section data off it — only its metadata.
        private static PeImage ProbePeHeader(string path)
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                                          FileShare.ReadWrite | FileShare.Delete);
            int want = (int)Math.Min(fs.Length, 64 * 1024);
            byte[] head = new byte[want];
            int total = 0;
            while (total < want)
            {
                int n = fs.Read(head, total, want - total);
                if (n == 0) break;
                total += n;
            }
            return PeImage.FromFile(head);
        }

        private static string FormatSize(long bytes)
        {
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            double v = bytes;
            int i = 0;
            while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
            return i == 0 ? $"{bytes} B" : $"{v:0.#} {units[i]}";
        }

        // Release the memory-mapped file backing a previously opened module's hex
        // view (closes the OS view + file handle). Called before pointing the hex
        // view at a different source (another file, a live process) or on close.
        private void DisposeFileMap()
        {
            if (_fileMap != null) { _fileMap.Dispose(); _fileMap = null; }
        }

        // A node was clicked in the call-graph (butterfly) view: select that
        // function everywhere — highlight it in the list, drive the hex/calls
        // views and any running capture, and re-centre the graph on it.
        private void OnGraphNeighborSelected(object? sender, ulong address)
        {
            FunctionList.SelectByAddress(address); // highlight in the list (silent)
            OnFunctionSelected(this, address);
        }

        // A string (or one of its referencing functions) was activated in the
        // Strings tab: jump to the function that references it — exactly as if it
        // were clicked in the function list (highlight it, re-centre the graph,
        // navigate the hex view, and, with auto-capture on, focus a live trace on
        // it). The string/xref data is from the static image, so it survives the
        // jump and the panel stays usable.
        private void OnStringFunctionActivated(object? sender, ulong address)
        {
            if (!FunctionList.SelectByAddress(address))
            {
                StatusText.Text = $"{DescribeAddr(address)} references the string, but isn't in the current function list.";
                return;
            }
            OnFunctionSelected(this, address);
        }

        // --- deferred Strings-tab scan ---------------------------------------

        // Arm a Strings-tab scan that runs only when the user first opens the Strings
        // tab (or immediately if it's already showing). Replaces any prior pending /
        // in-flight scan. Nothing is read or disassembled until then.
        private void ArmStringScan(Func<List<ExtractedString>> scan, TraceDataset ds)
        {
            _stringScanGen++;
            _pendingStringScan = scan;
            _pendingStringScanDs = ds;
            StringsPanel.Clear();
            StringsPanel.SetStatus("open this tab to load strings");
            if (StringsPanel.IsVisible) RunStringScan(); // already on the tab — load now
        }

        // Clear the Strings tab and cancel any pending / in-flight deferred scan.
        private void ClearStringsTab()
        {
            _stringScanGen++;
            _pendingStringScan = null;
            _pendingStringScanDs = null;
            StringsPanel.Clear();
        }

        // Run the armed scan once, on a worker thread, and populate when it finishes.
        // The scan AND the row-building (name resolution, view-model construction) both
        // run off the UI thread; only the final single-shot assignment touches the UI,
        // so even tens of thousands of strings never freeze the window.
        private void RunStringScan()
        {
            if (_pendingStringScan == null) return;
            var scan = _pendingStringScan;
            var ds = _pendingStringScanDs!;
            int gen = _stringScanGen;
            _pendingStringScan = null; // consume — runs at most once per arm
            StringsPanel.SetStatus("scanning strings…");
            Task.Run(() =>
            {
                var strings = scan();
                var names = new Dictionary<ulong, TracedFunction>();
                foreach (var f in ds.Functions) names[f.Address] = f;
                var map = new ModuleMap(ds.Modules);
                return StringsView.BuildRows(strings, addr =>
                {
                    string name = names.TryGetValue(addr, out var fn) ? (fn.Name ?? fn.DisplayName) : "sub_" + addr.ToString("X");
                    string module = map.Resolve(addr)?.Name ?? "";
                    return (name, module);
                });
            }).ContinueWith(t =>
            {
                if (gen != _stringScanGen) return; // a newer target superseded this scan
                if (t.IsCompletedSuccessfully)
                {
                    StringsPanel.SetRows(t.Result);
                    _diag.Add($"strings: {t.Result.Count} found.");
                }
                else
                {
                    StringsPanel.Clear();
                    StringsPanel.SetStatus("string scan failed");
                    _diag.Add("string scan failed: " + (t.Exception?.GetBaseException().Message ?? "?"));
                }
            }, System.Threading.CancellationToken.None, TaskContinuationOptions.None,
               TaskScheduler.FromCurrentSynchronizationContext());
        }

        // Mine the target for strings: the main image plus the app's own DLLs (the
        // non-OS modules), reading each live through the session on a worker thread.
        // The main/discovered modules carry full code cross-references (their
        // functions are known); the app DLLs are listed for their strings only (no
        // xref disassembly — their functions aren't in the function list to jump to).
        private static List<ExtractedString> ScanProcessStrings(LiveSession session, TraceDataset data)
        {
            var all = new List<ExtractedString>();
            foreach (var m in SelectAppModules(session, data))
            {
                var mfuncs = data.Functions.FindAll(f => m.Contains(f.Address)); // empty for an app DLL
                try { all.AddRange(StringScanner.ScanModule(session.Process, m, mfuncs)); }
                catch { /* a module we can't read is skipped */ }
                if (all.Count > 500000) break; // safety cap across modules
            }
            return all;
        }

        // The target's main image plus only the DLLs that ship with it — every loaded
        // module sitting in the main executable's own directory (or a subfolder of it).
        // This excludes the OS modules AND shared runtimes installed elsewhere (e.g. the
        // .NET runtime under Program Files), so the list is just the app's own files.
        // The discovered modules are always included so the main image is never dropped;
        // a module under \Windows\ is never added even if the app itself lives there.
        private static List<ModuleInfo> SelectAppModules(LiveSession session, TraceDataset data)
        {
            var result = new List<ModuleInfo>();
            var seen = new HashSet<ulong>();
            foreach (var m in data.Modules) if (seen.Add(m.BaseAddress)) result.Add(m);

            List<ModuleInfo> loaded;
            try { loaded = session.Process.EnumerateModules(); }
            catch { return result; }
            if (loaded.Count == 0) return result;

            // The app's directory = where the main executable (the first module) lives.
            string appDir = DirOf(loaded[0].Path);
            if (appDir.Length == 0) return result; // unknown — keep just the discovered set
            string windir = DirNorm(SafeFolder(Environment.SpecialFolder.Windows));

            foreach (var m in loaded)
            {
                if (!seen.Add(m.BaseAddress)) continue;
                string dir = DirOf(m.Path);
                if (dir.Length == 0) continue;
                bool inApp = dir.Equals(appDir, StringComparison.OrdinalIgnoreCase)
                          || dir.StartsWith(appDir + "\\", StringComparison.OrdinalIgnoreCase);
                bool isSystem = windir.Length > 0 &&
                    (dir.Equals(windir, StringComparison.OrdinalIgnoreCase)
                  || dir.StartsWith(windir + "\\", StringComparison.OrdinalIgnoreCase));
                if (inApp && !isSystem) result.Add(m);
            }
            return result;
        }

        private static string DirOf(string? path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            try { return DirNorm(System.IO.Path.GetDirectoryName(path)); } catch { return ""; }
        }
        private static string DirNorm(string? dir) =>
            string.IsNullOrEmpty(dir) ? "" : dir!.Replace('/', '\\').TrimEnd('\\');
        private static string SafeFolder(Environment.SpecialFolder f)
        {
            try { return Environment.GetFolderPath(f); } catch { return ""; }
        }

        private void OnFunctionSelected(object? sender, ulong address)
        {
            _selectedFunctionAddr = address;
            GraphView.SetSelected(address); // re-centre the call-graph (butterfly) view

            // Unconditional, immediate confirmation that the click registered.
            StatusText.Text = $"Selected {DescribeAddr(address)}.";

            // Navigate the hex view (Memory tab) to the function.
            if (_currentPe != null && _currentPe.TryVaToFileOffset(address, out uint off))
                Hex.GoTo(off);
            else
                Hex.GoTo(address);

            // Jump to this function's latest call in the Calls list. The full trace
            // is kept, so if it was ever called the row is present.
            bool listJumped = CallList.SelectLastFor(address);

            // Child-follow: viewing one followed process. No live session, so its
            // caller frames come from stack snapshots (like offline review).
            if (_childView && _liveDataset != null)
            {
                SetCallersTarget(address);
                StatusText.Text = listJumped
                    ? $"{DescribeAddr(address)} — latest call shown (pid {_childSelectedPid})."
                    : $"Selected {DescribeAddr(address)} (pid {_childSelectedPid}).";
                return;
            }

            // Offline review of a loaded trace: no live target, but we have a
            // dataset + records, so populate the caller tree / call stack and stop.
            if (_offlineTrace && _liveDataset != null)
            {
                SetCallersTarget(address);
                StatusText.Text = listJumped
                    ? $"{DescribeAddr(address)} — latest call shown (saved trace · offline review)."
                    : $"Selected {DescribeAddr(address)} (saved trace · offline review).";
                return;
            }

            if (_session == null || _liveDataset == null)
            {
                SetCallersTarget(0); // static file view: no live callers to show
                StatusText.Text = $"Selected {DescribeAddr(address)} — see the Memory tab for its bytes.";
                return; // static file view: nothing to trace
            }

            SetCallersTarget(address); // populate the "Called by" panel for this function

            if (AutoCapture.IsChecked != true)
            {
                StatusText.Text = listJumped
                    ? $"Jumped to the latest call of {DescribeAddr(address)} — Follow paused; re-check it to resume tailing."
                    : _captured.Exists(r => r.Destination == address)
                        ? $"{DescribeAddr(address)}: its calls dropped off the \"Keep last\" cap — raise or clear it to see them."
                        : $"Selected {DescribeAddr(address)} — no calls recorded for it yet.";
                return;
            }

            if (!Environment.Is64BitProcess && _session.Is64Bit)
            {
                StatusText.Text = "A 32-bit build can't instrument a 64-bit target. Rebuild as x64.";
                return;
            }

            if (_capture == null)
                StartLiveCapture();                  // nothing running: trace just this function
            else if (_apiCaptureMode)
                StatusText.Text = $"Inspecting callers of {DescribeAddr(address)} — broad Windows-API trace still running.";
            else if (_captureFocus != address)
                RefocusCaptureOn(address);           // a trace is running: switch it onto this one
            else
                StatusText.Text = $"Already tracing {DescribeAddr(address)} · {_captured.Count} call(s) recorded.";
        }

        // Switch a running trace (the broad startup trace, or another focused one)
        // onto just this function: restore the current hooks, then instrument only
        // it. The prior calls are cleared — Stop capture first to keep them.
        private void RefocusCaptureOn(ulong address)
        {
            if (_session == null || _liveDataset == null) return;
            if (!_liveDataset.Functions.Exists(f => f.Address == address))
            {
                StatusText.Text = "That entry isn't in the live module — can't refocus on it.";
                return;
            }
            StopCaptureQuietly();
            _diag.Add($"refocus live trace on {DescribeAddr(address)}");
            StartCaptureOn(new List<ulong> { address }, DescribeAddr(address), preserveLog: true);
        }

        // Tear down a running capture (restores the hooked bytes) without freezing
        // the recording into the view — used when switching to another function.
        private void StopCaptureQuietly()
        {
            _startupActive = false;
            if (_debugWatch != null) { _debugWatch.Stop(); _debugWatch = null; }
            if (_captureBursting) { _captureBursting = false; System.Windows.Input.Mouse.OverrideCursor = null; }
            if (_pollTimer != null) { _pollTimer.Stop(); _pollTimer.Tick -= OnPollTick; _pollTimer = null; }
            var cap = _capture;
            _capture = null;
            // If a background poll is in flight, its continuation disposes cap (it
            // sees _capture != cap); closing the handle here would pull it out from
            // under an in-progress ReadProcessMemory.
            if (cap != null && !_polling) { try { cap.Dispose(); } catch { } }
            UpdateClearCallsState();
        }

        // --- attach to a live process (read-only discovery) ------------------

        private async void OnAttach(object sender, RoutedEventArgs e)
        {
            var picker = new ProcessPickerWindow { Owner = this };
            if (picker.ShowDialog() != true || picker.SelectedPid < 0) return;

            int pid = picker.SelectedPid;
            string label = picker.SelectedEntry?.Name ?? pid.ToString();
            _diag.Clear();
            Diag($"attach: {label} ({pid}) — discovering…");
            SetCallersTarget(0);
            _offlineTrace = false;
            _childView = false;
            ClearStringsTab(); // armed below to scan the live process image when the tab is opened

            System.Windows.Input.Mouse.OverrideCursor = System.Windows.Input.Cursors.Wait;
            try
            {
                // Enumeration + code scanning can be slow; keep the UI responsive.
                var session = await Task.Run(() => LiveSession.Attach(pid));

                _session?.Dispose();
                _session = session;
                _currentPe = null;
                _is64 = session.Is64Bit;
                _moduleMap = session.Modules;
                _selectedFunctionAddr = 0;

                var data = session.Dataset;
                _liveDataset = data;
                _model.Load(data);
                GraphView.SetModel(_model);
                PlayBar.SetData(data);
                FunctionList.LoadFromDataset(data);
                DisposeFileMap();
                Hex.SetSource(session.Process,
                    data.Functions.Count > 0 ? data.Functions[0].Address : session.Process.MinAddress);

                Diag($"✓ attached to {label} ({pid}) · {(session.Is64Bit ? "x64" : "x86")} · " +
                     $"{data.Functions.Count} functions · {data.Records.Count} call sites (read-only)");

                // Strings tab (like IDA's Strings window): ARM a deferred scan of the
                // discovered module(s), read live via ReadProcessMemory. It runs only
                // when the user opens the Strings tab, so attach stays fast.
                ArmStringScan(() => ScanProcessStrings(session, data), data);
            }
            catch (Exception ex)
            {
                Diag("attach failed: " + ex.Message);
            }
            finally
            {
                System.Windows.Input.Mouse.OverrideCursor = null;
            }
        }

        // --- live capture (active instrumentation) ---------------------------

        private async void OnLaunchCapture(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Launch an executable and capture from the start",
                Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
            };
            if (dlg.ShowDialog(this) != true) return;

            _startupPath = dlg.FileName;
            _startupName = Path.GetFileName(_startupPath);
            _disableAslr = DisableAslr.IsChecked == true;
            _bisecting = false;
            _bisectArmOnly = null;
            _bisectDeadline = 0;
            _bisectRelaunches = 0;
            _startupStop = false;
            _diag.Clear();

            await LaunchStartupTrace();
        }

        // The startup trace: launch suspended, discover, arm a broad set, attach the
        // crash watch BEFORE resuming, then wire up the live views. On a crash the
        // watch reports it live and pins/writes the culprit; only an auto-bisection
        // search relaunches (its test runs hidden).
        private async Task LaunchStartupTrace()
        {
            string path = _startupPath!;
            string name = _startupName ?? Path.GetFileName(path);

            // A generation token: if the user fires another launch while this one's
            // post-start setup is still awaiting, the superseded coroutine bails
            // instead of pointing the UI at its now-dead target.
            int gen = ++_startupGeneration;

            if (_startupStop) return; // user hit Stop before this (relaunched) attempt got going

            StopCaptureQuietly();
            StopDllCapture();
            StopChildFollow();
            _captured.Clear();
            _autoUnhooked.Clear();
            ClearStringsTab(); // armed once the target is running (deferred until the tab is opened)
            _maxCursorSeen = 0;
            _captureFocus = 0;
            SetCallersTarget(0);
            _apiCaptureMode = false;
            _offlineTrace = false;
            _childView = false;
            _startupSortedEntries = null;
            _startupHookedSet = null;
            _startupRetCache.Clear();
            _faultSeenThisAttempt = false;
            _crashAppendedThisAttempt = false;

            // Read the EXE up front: bitness + size, so we can discover and hook its
            // functions while it is still frozen at creation.
            PeImage exe;
            byte[] exeBytes;
            try { exeBytes = File.ReadAllBytes(path); exe = PeImage.FromFile(exeBytes); }
            catch (Exception ex) { Diag($"couldn't read {name}: {ex.Message}"); return; }

            if (!Environment.Is64BitProcess && exe.Is64Bit)
            {
                Diag("a 32-bit build can't instrument a 64-bit target. Rebuild CDA as x64.");
                return;
            }

            Diag(_bisecting
                ? $"launch (suspended startup trace): {name} — hidden bisection test"
                : $"launch (suspended startup trace): {name}" + (_disableAslr ? " (ASLR disabled)" : ""));

            // Hidden launch during a bisection search so the repeatedly-relaunched
            // target doesn't pop up or steal focus; shown for the first attempt and the
            // user's manual re-launches.
            //
            // With "Disable ASLR" on, launch a fixed-base copy (DYNAMICBASE stripped)
            // so the image maps at its preferred base every run — reproducible
            // addresses. Discovery, display, and the skip-list keep using the original
            // path (the copy is byte-identical but for the two header bits).
            string launchPath = path;
            if (_disableAslr)
            {
                try
                {
                    launchPath = FixedBaseImage.Create(path);
                    _diag.Add(launchPath != path
                        ? $"ASLR: launching a fixed-base copy ({Path.GetFileName(launchPath)}) so the image base is stable across runs"
                        : "ASLR: image already has DYNAMICBASE off — its preferred base is already fixed");
                    if (launchPath != path) _fixedBaseOriginals.Add(path);
                }
                catch (Exception ex)
                {
                    _diag.Add($"ASLR: couldn't write a fixed-base copy ({ex.Message}); relying on the bottom-up mitigation policy only");
                    launchPath = path;
                }
            }

            SuspendedProcess proc;
            try { proc = SuspendedProcess.Create(launchPath, hidden: _bisecting, disableAslr: _disableAslr); }
            catch (Exception ex) { Diag($"couldn't launch {name}: {ex.Message}"); return; }

            int pid = proc.Pid;
            _selectedFunctionAddr = 0;
            bool armed = false;

            // The discovery scan and the graph/list build below run partly on this
            // (UI) thread, so the window is briefly unresponsive. Show a busy cursor
            // until everything is wired up; it's cleared (with a "ready" message) in
            // the finally at the end, on every path.
            System.Windows.Input.Mouse.OverrideCursor = System.Windows.Input.Cursors.Wait;

            // === instrument BEFORE the first instruction runs ================
            ulong imageBase = proc.GetImageBase();
            _diag.Add($"image base=0x{imageBase:X}");
            if (imageBase != 0)
            {
                try
                {
                    // Discover the main module while the process is frozen (its image
                    // is already mapped), then arm a broad set of its functions so the
                    // startup call flow is captured.
                    var (funcs, edges) = await Task.Run(() => DiscoverModuleSuspended(exeBytes, exe, imageBase));
                    _diag.Add($"suspended discovery (on-disk image, rebased to 0x{imageBase:X}): {funcs.Count} functions, {edges.Count} call sites");

                    var discovered = BuildUiDataset(name, imageBase, exe.SizeOfImage, path, funcs, edges);
                    // NOTE: the Strings tab is filled AFTER the target is running (see the
                    // background scan post-resume) — mining strings disassembles the image
                    // and must never sit in the suspended/arm/resume critical path.

                    if (funcs.Count < MinPreRunFunctions)
                    {
                        // Almost always a packed/compressed executable: the real
                        // code is decompressed into memory at startup, so only the
                        // unpacker stub is visible now. Hooking it would corrupt the
                        // unpacking and the program would never launch — skip pre-run
                        // hooking and trace the real code after startup instead.
                        _diag.Add($"pre-run discovery found only {funcs.Count} function(s) (< {MinPreRunFunctions}) — likely packed; NOT hooking before run. Will trace after startup.");
                    }
                    else
                    {
                        var candidates = BuildStartupCandidates(funcs, edges, skipTop: 16, max: StartupCandidatePool);

                        // Static skip-list: drop functions that can't tolerate an inline
                        // .text splice so the rest can be traced. RVAs from the image base,
                        // read fresh each launch from cda_hook_skip.txt — no relaunch, no
                        // flood. Ensure the canonical file exists so it's always findable.
                        string skipFile = EnsureSkipListExists();
                        _diag.Add($"skip-list file: {skipFile}");
                        var (skipRvas, skipProbe) = ReadStartupSkipRvas();
                        _diag.Add(skipProbe);
                        if (skipRvas.Count > 0)
                        {
                            int before = candidates.Count;
                            candidates = candidates.FindAll(a => !skipRvas.Contains(a - imageBase));
                            _diag.Add($"hook skip-list: excluded {before - candidates.Count} function(s) by RVA — tracing the rest.");
                        }

                        // During an auto-bisection search, arm ONLY the current test
                        // subset so we can tell whether it contains the culprit.
                        if (_bisectArmOnly != null)
                            candidates = candidates.FindAll(a => _bisectArmOnly.Contains(a));

                        _diag.Add(_bisectArmOnly != null
                            ? $"bisection test: arming {Math.Min(candidates.Count, StartupTraceFunctions)} suspect hook(s) (hidden)…"
                            : $"startup trace: arming up to {Math.Min(candidates.Count, StartupTraceFunctions)} function(s)…");

                        // Pass the main module so the entry-point guard can do its
                        // authoritative .pdata check even though we're pre-loader:
                        // the process is still suspended here, so live module
                        // enumeration inside Start would come back empty and the
                        // guard would silently fall back to a weak heuristic that
                        // lets non-entry targets through (→ int3 on resume). The
                        // mapped image's .pdata is readable now, we just have to tell
                        // the guard the module is there.
                        _capture = CaptureSession.Start(pid, candidates,
                            maxFunctions: StartupTraceFunctions, bufferRecords: StartupBufferRecords,
                            out int instrumented, out int skipped, out string? firstError,
                            knownModules: discovered.Modules);
                        _diag.Add($"capture.Start: instrumented={instrumented} skipped={skipped} firstError={firstError ?? "(none)"}");

                        // Always show where the bisection range file was looked for and
                        // what each path held (this line also proves the running build
                        // actually contains the range logic).
                        if (_capture?.HookRangeProbe != null) _diag.Add(_capture.HookRangeProbe);

                        // When a slice is active, list exactly which functions were
                        // hooked (RVA from the image base) so a surviving crash can be
                        // tied to specific entries.
                        if (_capture?.HookRange != null)
                        {
                            var hooked = _capture.HookedTargets;
                            int showN = Math.Min(hooked.Count, 64);
                            var rvas = new List<string>(showN);
                            for (int i = 0; i < showN; i++) rvas.Add($"+0x{hooked[i] - imageBase:X}");
                            string more = hooked.Count > showN ? $" (+{hooked.Count - showN} more)" : "";
                            _diag.Add($"hook range {_capture.HookRange} → hooked {hooked.Count}: {string.Join(" ", rvas)}{more}");
                        }

                        if (instrumented > 0)
                        {
                            _is64 = exe.Is64Bit;
                            _moduleMap = new ModuleMap(discovered.Modules);
                            _liveDataset = discovered;
                            _model.Load(discovered);
                            GraphView.SetModel(_model);
                            PlayBar.SetData(discovered);
                            FunctionList.LoadFromDataset(discovered);
                            CallList.Configure(_moduleMap);
                            CallList.Clear();
                            _pollTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
                            _pollTimer.Tick += OnPollTick;
                            _pollTimer.Start();

                            // Snapshot the entry index + the armed set so a live fault
                            // can be floored to the hooked function that caused it, and
                            // the image base so the culprit becomes a stable RVA.
                            _startupActive = true;
                            _startupImageBase = imageBase;
                            _startupHookedSet = new HashSet<ulong>(_capture!.HookedTargets);
                            var entryAddrs = discovered.Functions.ConvertAll(f => f.Address);
                            entryAddrs.Sort();
                            _startupSortedEntries = entryAddrs.ToArray();

                            // Attach a debugger on the side BEFORE the target is
                            // resumed, so a fault a spliced hook causes is caught live
                            // and pinned to the hook that caused it, instead of just
                            // killing the target with an opaque exit code. A failed
                            // attach degrades to the old free-run mode.
                            _debugWatch = new DebugCrashWatch(pid);
                            _debugWatch.Log += OnStartupCrashWatchLog;
                            _debugWatch.Crash += OnStartupCrash;
                            _debugWatch.Start();
                            bool attached = await Task.Run(() => _debugWatch!.WaitUntilAttached(3000));
                            _diag.Add(attached
                                ? "crash watch: debugger attached — a hook-induced fault will be caught live and pinned to its hook."
                                : "crash watch: couldn't attach a debugger; running without live fault capture (a crash will only show an exit code).");

                            armed = true;
                        }
                        else { _capture?.Dispose(); _capture = null; }
                    }
                }
                catch (Exception ex)
                {
                    _diag.Add("suspended prep failed: " + ex.Message);
                    if (_debugWatch != null) { _debugWatch.Stop(); _debugWatch = null; }
                    _capture?.Dispose();
                    _capture = null;
                }
            }
            else
            {
                _diag.Add("couldn't resolve image base; falling back to attach-after-start");
            }

            // === release the program =========================================
            // A CREATE_SUSPENDED target shows no window until resumed — the last point
            // we can abort silently. If the user hit Stop while we were arming, tear
            // down and kill the (never-resumed) target instead of letting it run.
            if (_startupStop)
            {
                _diag.Add("startup trace stopped before launch — target not resumed.");
                if (_debugWatch != null) { _debugWatch.Stop(); _debugWatch = null; }
                StopCapture();
                try { TargetProcess.Kill(pid); } catch { }
                proc.Dispose();
                if (!_captureBursting) System.Windows.Input.Mouse.OverrideCursor = null;
                return;
            }

            proc.Resume();
            _diag.Add(armed ? "resumed target (hooks already armed)" : "resumed target (no startup hooks)");
            proc.Dispose();

            // For a bisection test: if it runs BisectSurviveMs with no fatal fault, the
            // poll loop declares the subset clean (passed).
            _bisectDeadline = (armed && _bisecting && _bisectArmOnly != null)
                ? Environment.TickCount64 + BisectSurviveMs
                : 0;

            // Defensive: a bisection test that armed nothing (shouldn't happen — these
            // hooks armed in the run that started the search) has no poll timer to drive
            // the survive check, which would stall the search. Abort it cleanly.
            if (_bisecting && _bisectArmOnly != null && !armed)
            {
                Diag("bisection: the test subset armed no hooks — stopping the search.");
                _bisecting = false; _bisectArmOnly = null; _bisectDeadline = 0;
            }

            if (armed)
                Diag($"startup trace: {_capture!.HookedCount} hook(s) armed before launch — capturing startup…");

            // Establish a full live session for the UI (hex source, click-to-focus),
            // and — if we couldn't arm startup hooks — fall back to the post-start
            // single-function mode that we know works.
            await Task.Delay(armed ? 400 : 800);
            try
            {
                var session = await Task.Run(() => LiveSession.Attach(pid));

                // A crash during the post-start window may have superseded this attempt
                // with a relaunch; if so, drop this (dead) target's session rather than
                // overwrite the live one the new attempt just established.
                if (gen != _startupGeneration) { session.Dispose(); return; }

                _session?.Dispose();
                _session = session;
                _currentPe = null;
                _is64 = session.Is64Bit;
                _moduleMap = session.Modules;
                DisposeFileMap();
                Hex.SetSource(session.Process,
                    session.Dataset.Functions.Count > 0 ? session.Dataset.Functions[0].Address : session.Process.MinAddress);

                if (armed)
                {
                    _diag.Add($"post-start attach ok: {session.Dataset.Functions.Count} functions (UI/focus session)");
                    Diag($"✓ Ready · startup trace running · {_capture!.HookedCount} hook(s) — use the program; click a function to focus on just it.");
                }
                else
                {
                    var data = session.Dataset;
                    _liveDataset = data;
                    _selectedFunctionAddr = 0;
                    _model.Load(data);
                    GraphView.SetModel(_model);
                    PlayBar.SetData(data);
                    FunctionList.LoadFromDataset(data);
                    _diag.Add($"attach ok (post-start): {data.Functions.Count} functions, {data.Modules.Count} module(s)");

                    if (data.Functions.Count == 0)
                    {
                        Diag($"launched {name} ({pid}) but found no functions to instrument (managed/.NET or stripped?).");
                    }
                    else if (AutoCapture.IsChecked == true && !(!Environment.Is64BitProcess && session.Is64Bit))
                    {
                        // Broad trace of the now-running (and, if packed, unpacked)
                        // real code we deliberately didn't hook before the run.
                        var edges = new List<(ulong Site, ulong Target)>(data.Records.Count);
                        foreach (var rec in data.Records) edges.Add((rec.Source, rec.Destination));
                        var candidates = BuildStartupCandidates(data.Functions, edges, skipTop: 16, max: StartupCandidatePool);
                        _diag.Add($"post-start broad trace: arming up to {Math.Min(candidates.Count, StartupTraceFunctions)} of {candidates.Count} candidate(s)…");
                        StartCaptureOn(candidates, name, maxFunctions: StartupTraceFunctions, bufferRecords: StartupBufferRecords);
                    }
                    else
                    {
                        Diag($"launched {name} ({pid}) · {data.Functions.Count} functions. Click one to trace it.");
                    }
                }

                // Strings tab: ARM a deferred scan of the now-running image. It does
                // not run until the user actually opens the Strings tab — so it never
                // touches the suspended/arm/resume critical path, and never reads the
                // target's memory at all unless the strings are wanted. Reading the live
                // image also picks up an unpacked target's real strings.
                if (_session != null && _liveDataset != null)
                {
                    var bgSession = _session;
                    var bgData = _liveDataset;
                    ArmStringScan(() => ScanProcessStrings(bgSession, bgData), bgData);
                }
            }
            catch (Exception ex)
            {
                _diag.Add($"post-start attach failed: {ex.Message}");
                if (!armed) Diag($"launched {name} ({pid}) but attach failed: {ex.Message}");
            }
            finally
            {
                // Scan/launch finished — restore the cursor unless a heavy startup
                // flood is still being drained (the poll loop owns the cursor then,
                // and clears it once the batches subside).
                if (!_captureBursting) System.Windows.Input.Mouse.OverrideCursor = null;
            }
        }

        // The crash watch's own log lines (attach failures, etc.) — marshal to the UI.
        private void OnStartupCrashWatchLog(string s) =>
            Dispatcher.BeginInvoke(new Action(() => _diag.Add(s)));

        // A fault the side debugger caught in the startup-traced target. Raised on the
        // watch thread while the target is frozen at the fault; marshal to the UI to
        // report it and, when it can be pinned to a hook, AUTO-ADD that hook's RVA to
        // the skip-list so the next launch traces past it. It does NOT relaunch — the
        // exclusion list builds itself, you decide when to launch again.
        private void OnStartupCrash(DebugCrashWatch.CrashInfo info)
        {
            try
            {
                Dispatcher.Invoke(() =>
                {
                    _diag.Add(info.Line);
                    _faultSeenThisAttempt = true;

                    // During a bisection search we only need the crashed/survived verdict,
                    // not an attribution — the search itself isolates the culprit.
                    if (_bisecting) return;

                    ulong culprit = AttributeStartupCrash(info);
                    if (culprit != 0 && _startupImageBase != 0)
                    {
                        ulong rva = culprit - _startupImageBase;
                        string nm = _fnNames.TryGetValue(culprit, out var n) ? n : DescribeAddr(culprit);
                        string? wrote = AppendToSkipList(rva, nm);
                        _crashAppendedThisAttempt = true; // pinned -> no need to bisect
                        _diag.Add(wrote != null
                            ? $"crash pinned to hooked {nm} (+0x{rva:X}) — ADDED to the skip-list ({wrote}). Re-launch (Launch & capture) to trace past it."
                            : $"crash pinned to hooked {nm} (+0x{rva:X}) — already in the skip-list. Re-launch to trace past it.");
                    }
                    else
                    {
                        _diag.Add(AutoBisectCrashes?.IsChecked == true
                            ? "crash not attributable to a single hook (deferred / cross-module corruption) — auto-bisecting to isolate it…"
                            : "crash not attributable to a single hook (deferred / cross-module corruption) — turn on 'Auto-bisect crashes' to isolate it, or bisect with CDA_HOOK_RANGE.");
                    }
                });
            }
            catch { /* dispatcher gone — app shutting down */ }
        }

        // Blame a hooked function for the fault, strongest signal first: the fault
        // landed in a hook's own generated code (entry/stub/trampoline); else it's
        // inside a hooked function's body (it ran a corrupted value); else it's a
        // deferred fault and we blame the innermost hooked frame still on the
        // crashing thread's stack. Returns 0 if no hook is implicated.
        private ulong AttributeStartupCrash(DebugCrashWatch.CrashInfo info)
        {
            var cap = _capture;
            if (cap == null) return 0;

            ulong owner = cap.OwningHook(info.FaultIp);
            if (owner != 0) return owner;

            ulong atFault = EnclosingHookedFunction(info.FaultIp);
            if (atFault != 0) return atFault;

            // Deferred fault: blame the innermost hooked frame on the crashing stack —
            // but only count a word that is a genuine return address (a CALL ends just
            // before it), so a stray code-looking data word can't implicate an
            // innocent hook.
            foreach (ulong w in info.StackWords)
            {
                if (!LooksLikeStartupReturnAddress(w)) continue;
                ulong fn = EnclosingHookedFunction(w);
                if (fn != 0) return fn;
            }
            return 0;
        }

        // As LooksLikeReturnAddress, but reads through the live capture session's
        // handle (available during a crash even before the read-only UI session has
        // attached) and caches per target. Validates that <addr> is preceded by a CALL.
        private bool LooksLikeStartupReturnAddress(ulong addr)
        {
            var cap = _capture;
            if (cap == null || addr <= 8) return false;
            if (_startupRetCache.TryGetValue(addr, out bool ok)) return ok;
            byte[] b = new byte[8]; // bytes at [addr-8 .. addr)
            ok = cap.ReadTarget(addr - 8, b) == 8 && BytesPrecedingAreCall(b);
            _startupRetCache[addr] = ok;
            return ok;
        }

        // Floor an address to the discovered function that contains it, returning that
        // function's entry only if it is one we hooked this attempt (else 0). A coarse
        // span guard keeps a discovery hole from blaming a far-away entry.
        private ulong EnclosingHookedFunction(ulong addr)
        {
            var entries = _startupSortedEntries;
            var hooked = _startupHookedSet;
            if (entries == null || hooked == null || addr == 0) return 0;

            int i = Array.BinarySearch(entries, addr);
            if (i < 0) i = ~i - 1;                  // greatest entry <= addr
            if (i < 0 || i >= entries.Length) return 0;

            ulong start = entries[i];
            ulong next = i + 1 < entries.Length ? entries[i + 1] : ulong.MaxValue;
            if (addr < start || addr >= next) return 0;
            if (addr - start > 0x100000) return 0;  // implausibly far into a discovery hole
            return hooked.Contains(start) ? start : 0;
        }

        // --- tamed auto-bisection of an unattributable startup crash ---------
        // Binary-search the armed set for the single hook that crashes the target, each
        // test relaunching HIDDEN. Isolates ONE culprit, writes its RVA to the skip-list,
        // and stops — the user's manual re-launches converge the rest. Bounded by
        // MaxBisectRelaunches and cancelled by Stop. Assumes one culprit per search; an
        // interaction just gets a (possibly innocent) RVA excluded, surfaced next launch.

        private void BeginBisection(List<ulong> armedPool)
        {
            _bisecting = true;
            _bisectPool = armedPool.ToArray();   // candidate-install order, deterministic across relaunches
            _bisectLo = 0;
            _bisectHi = _bisectPool.Length;       // arming [lo,hi) (all) is known to crash
            int levels = (int)Math.Ceiling(Math.Log2(Math.Max(2, _bisectPool.Length)));
            Diag($"auto-bisecting {_bisectPool.Length} armed hook(s) to isolate the crash (~{levels} hidden relaunches)…");
            BisectAdvance();
        }

        // Start the next hidden test, or finish when the window narrows to one culprit /
        // the cap or Stop is hit.
        private void BisectAdvance()
        {
            if (_startupStop || AutoBisectCrashes?.IsChecked != true || _bisectRelaunches >= MaxBisectRelaunches)
            {
                bool capped = _bisectRelaunches >= MaxBisectRelaunches;
                _bisecting = false; _bisectArmOnly = null;
                Diag(capped
                    ? $"auto-bisection hit its relaunch ceiling ({MaxBisectRelaunches}) without isolating the crash — stopping. Try the CDA_HOOK_RANGE bisection."
                    : "auto-bisection stopped.");
                if (StatusText != null) StatusText.Text = "Auto-bisection stopped.";
                return;
            }

            if (_bisectHi - _bisectLo <= 1)
            {
                ulong found = _bisectPool[_bisectLo];
                _bisecting = false; _bisectArmOnly = null;
                string nm = _fnNames.TryGetValue(found, out var n) ? n : DescribeAddr(found);
                if (_startupImageBase != 0)
                {
                    ulong rva = found - _startupImageBase;
                    string? wrote = AppendToSkipList(rva, nm);
                    Diag(wrote != null
                        ? $"auto-bisection isolated the crash to hooked {nm} (+0x{rva:X}) — ADDED to the skip-list ({wrote}). Launch & capture again to trace past it."
                        : $"auto-bisection isolated the crash to hooked {nm} (+0x{rva:X}) — already in the skip-list. Launch & capture again to trace past it.");
                }
                if (StatusText != null) StatusText.Text = "Auto-bisection done — Launch & capture again for the clean trace.";
                return;
            }

            _bisectMid = (_bisectLo + _bisectHi) / 2;
            var sub = new HashSet<ulong>();
            for (int i = _bisectLo; i < _bisectMid; i++) sub.Add(_bisectPool[i]);
            _bisectArmOnly = sub;
            _bisectRelaunches++;
            Diag($"bisecting: testing {sub.Count} suspect hook(s) — indices [{_bisectLo}..{_bisectMid}) of [{_bisectLo}..{_bisectHi}) (hidden)…");
            _ = LaunchStartupTrace();
        }

        // Fold one hidden test's verdict into the search window, then advance.
        private void BisectStep(bool crashed)
        {
            Diag(crashed
                ? "  bisection: subset CRASHED — the culprit is inside it."
                : "  bisection: subset survived — the culprit is in the other half.");
            if (crashed) _bisectHi = _bisectMid;  // culprit in [lo, mid)
            else _bisectLo = _bisectMid;          // culprit in [mid, hi)
            BisectAdvance();
        }

        // --- launch a host & capture a DLL from the moment it loads ----------

        private void OnLaunchDllCapture(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Pick a DLL to trace from the moment it loads (DllMain)",
                Filter = "Dynamic libraries (*.dll)|*.dll|All files (*.*)|*.*",
            };
            if (dlg.ShowDialog(this) != true) return;

            string dllPath = dlg.FileName;
            string dllName = Path.GetFileName(dllPath);

            PeImage dllPe;
            try { dllPe = PeImage.FromFile(File.ReadAllBytes(dllPath)); }
            catch (Exception ex) { Diag($"couldn't read {dllName}: {ex.Message}"); return; }

            if (!Environment.Is64BitProcess && dllPe.Is64Bit)
            {
                Diag("a 32-bit build can't instrument a 64-bit DLL. Rebuild CDA as x64.");
                return;
            }

            // A DLL needs a host to load it. Default to rundll32 of the DLL's
            // bitness (it LoadLibrary's the DLL, which runs DllMain); or let the
            // user point at the real app that loads it.
            var hostDlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = $"Optional: a host EXE that loads {dllName}  (Cancel = use rundll32)",
                Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
            };
            bool disableAslr = DisableAslr.IsChecked == true;
            string hostPath, commandLine;
            string targetDll = dllPath; // the DLL DebugLoadCapture matches on load and reads on disk
            if (hostDlg.ShowDialog(this) == true)
            {
                hostPath = hostDlg.FileName;
                commandLine = "\"" + hostPath + "\"";
                if (disableAslr)
                    Diag("ASLR: a custom host controls how the DLL is loaded, so a fixed DLL base can't be forced from here — the bottom-up mitigation policy still applies. Use the default rundll32 host for a fixed DLL base.");
            }
            else
            {
                string sys = dllPe.Is64Bit
                    ? Environment.GetFolderPath(Environment.SpecialFolder.System)     // System32 (64-bit)
                    : Environment.GetFolderPath(Environment.SpecialFolder.SystemX86); // SysWOW64 (32-bit)
                hostPath = Path.Combine(sys, "rundll32.exe");
                if (disableAslr)
                {
                    try
                    {
                        targetDll = FixedBaseImage.Create(dllPath);
                        if (targetDll != dllPath)
                        {
                            Diag($"ASLR: loading a fixed-base copy of {dllName} ({Path.GetFileName(targetDll)}) so its base is stable across runs");
                            _fixedBaseOriginals.Add(dllPath);
                        }
                    }
                    catch (Exception ex)
                    {
                        Diag($"ASLR: couldn't write a fixed-base DLL copy ({ex.Message}); relying on the bottom-up mitigation policy only");
                        targetDll = dllPath;
                    }
                }
                commandLine = "\"" + hostPath + "\" \"" + targetDll + "\",#1";
            }

            StopCaptureQuietly();
            StopDllCapture();
            StopChildFollow();
            _captured.Clear();
            _maxCursorSeen = 0;
            _captureFocus = 0;
            _diag.Clear();
            Diag($"DLL capture: {dllName} via {Path.GetFileName(hostPath)} (waiting for load…)");
            SetCallersTarget(0);
            _apiCaptureMode = false;
            _offlineTrace = false;
            _childView = false;
            ClearStringsTab(); // DLL-at-load capture doesn't mine the strings tab

            _dllCapture = new DebugLoadCapture(hostPath, commandLine, targetDll,
                StartupTraceFunctions, StartupCandidatePool, StartupBufferRecords,
                disableAslr: disableAslr);
            _dllCapture.Log += m => Dispatcher.BeginInvoke(new Action(() => Diag(m)));
            _dllCapture.TargetExited += () => Dispatcher.BeginInvoke(new Action(() =>
            {
                Diag("DLL capture: host exited.");
                StopCapture();
            }));
            _dllCapture.DllHooked += h => Dispatcher.BeginInvoke(new Action(() => OnDllHooked(h)));
            _dllCapture.Start();
            UpdateClearCallsState();
        }

        // Raised (marshalled to the UI thread) once the target DLL is hooked at
        // load: wire up the views and begin polling for its DllMain/startup calls.
        private async void OnDllHooked(DebugLoadCapture.HookedDll h)
        {
            if (h.Instrumented <= 0)
            {
                Diag($"{h.Module.Name} loaded but no functions could be hooked ({h.FirstError ?? "no candidate"}).");
                h.Session.Dispose();
                return;
            }

            _capture = h.Session;
            _is64 = h.Is64Bit;
            _liveDataset = h.Dataset;
            _currentPe = null;
            _selectedFunctionAddr = 0;
            _captureFocus = 0; // broad trace
            _apiCaptureMode = false;
            _moduleMap = new ModuleMap(h.Dataset.Modules);
            _captured.Clear();
            _autoUnhooked.Clear();
            _maxCursorSeen = 0;

            _model.Load(h.Dataset);
            GraphView.SetModel(_model);
            PlayBar.SetData(h.Dataset);
            FunctionList.LoadFromDataset(h.Dataset);
            CallList.Configure(_moduleMap);
            CallList.Clear();

            _pollTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
            _pollTimer.Tick += OnPollTick;
            _pollTimer.Start();
            Diag($"tracing {h.Module.Name} from load · {h.Instrumented} hook(s) armed before DllMain — capturing…");

            // Attach a read-only live session so the hex view has bytes and
            // click-to-refocus works; widen the module map for better resolution.
            try
            {
                var session = await Task.Run(() => LiveSession.Attach(h.Pid));
                _session?.Dispose();
                _session = session;
                _moduleMap = session.Modules;
                CallList.Configure(_moduleMap);
                DisposeFileMap();
                Hex.SetSource(session.Process, h.Module.BaseAddress);
                _diag.Add($"post-hook attach ok: {session.Dataset.Functions.Count} functions (UI/focus session)");
            }
            catch (Exception ex) { _diag.Add("post-hook attach failed: " + ex.Message); }
        }

        private void StopDllCapture()
        {
            if (_dllCapture != null) { _dllCapture.Stop(); _dllCapture = null; }
            UpdateClearCallsState();
        }

        // --- follow a process and its children (instrument the whole tree) ----

        // Launch an executable under a DEBUG_PROCESS debug loop that follows every
        // process it spawns, and instrument each one at the moment it starts
        // (frozen at creation, before its code runs) using the same startup-trace
        // path as Launch & capture. Per-process call counts stream into the
        // diagnostics; the records themselves aren't routed into the single-target
        // graph/calls views yet (that's the next stage). Stop capture removes the
        // hooks and detaches, leaving the tree running.
        private void OnFollowChildren(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Launch an executable and follow + instrument the process tree it spawns",
                Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
            };
            if (dlg.ShowDialog(this) != true) return;

            // Don't run alongside another capture/observer.
            StopCaptureQuietly();
            StopDllCapture();
            StopChildFollow();
            _diag.Clear();

            // Fresh multi-target state for this run; reveal the target picker.
            ResetChildTargets();
            ChildTargetPanel.Visibility = Visibility.Visible;
            ClearStringsTab(); // per-process tree capture doesn't drive the strings tab

            string path = dlg.FileName;
            bool skipSystem = FollowSkipSystem.IsChecked == true;
            bool disableAslr = DisableAslr.IsChecked == true;
            Diag($"follow tree: launching {Path.GetFileName(path)} under DEBUG_PROCESS — instrumenting each process as it starts" +
                 (skipSystem ? " (system/OS children skipped)…" : " (including system/OS children)…"));

            // Fixed-base only the root we launch; processes the tree spawns are out of
            // our control and keep their own ASLR (the bottom-up mitigation policy is
            // still applied to each via DEBUG_PROCESS). Launch a DYNAMICBASE-stripped
            // copy of the root for a stable base.
            string launchPath = path;
            if (disableAslr)
            {
                try
                {
                    launchPath = FixedBaseImage.Create(path);
                    if (launchPath != path)
                    {
                        Diag($"ASLR: launching a fixed-base copy of the root ({Path.GetFileName(launchPath)}); spawned children keep their own ASLR");
                        _fixedBaseOriginals.Add(path);
                    }
                }
                catch (Exception ex)
                {
                    Diag($"ASLR: couldn't write a fixed-base copy ({ex.Message}); relying on the bottom-up mitigation policy only");
                    launchPath = path;
                }
            }

            var follow = new ChildFollowCapture(launchPath,
                StartupTraceFunctions, StartupCandidatePool, StartupBufferRecords, MinPreRunFunctions,
                skipSystemProcesses: skipSystem, disableAslr: disableAslr);
            follow.Log += m => Dispatcher.BeginInvoke(new Action(() => Diag(m)));
            follow.ProcessHooked += hp => Dispatcher.BeginInvoke(new Action(() => OnChildProcessHooked(hp)));
            follow.RecordsCaptured += (pid, recs) => Dispatcher.BeginInvoke(new Action(() => OnChildRecords(pid, recs)));
            follow.ProcessExited += pid => Dispatcher.BeginInvoke(new Action(() => OnChildProcessExited(pid)));
            follow.TreeExited += () => Dispatcher.BeginInvoke(new Action(() =>
            {
                Diag("follow tree: process tree finished.");
                StopChildFollow();
            }));
            _childFollow = follow;
            follow.Start();
            UpdateClearCallsState();
        }

        private void StopChildFollow()
        {
            if (_childFollow != null) { _childFollow.Stop(); _childFollow = null; }
            UpdateClearCallsState();
        }

        // --- child-follow multi-target view (Stage 3) -------------------------

        // Drop all per-target state (called when a new follow run starts). Leaves
        // other modes untouched.
        private void ResetChildTargets()
        {
            _childTargets.Clear();
            _childItems.Clear();
            _childSelectedPid = -1;
            _childView = false;
        }

        // A process in the tree was instrumented: register it as a selectable
        // target. Auto-select the first one so its calls are visible immediately.
        private void OnChildProcessHooked(ChildFollowCapture.HookedProcess hp)
        {
            if (_childTargets.ContainsKey(hp.Pid)) return;

            string image = hp.Dataset.Modules.Count > 0 ? hp.Dataset.Modules[0].Name : ("pid " + hp.Pid);
            var item = new ChildTargetItem { Pid = hp.Pid };
            var t = new ChildTarget
            {
                Pid = hp.Pid,
                Is64 = hp.Is64Bit,
                Image = image,
                Dataset = hp.Dataset,
                ModuleMap = new ModuleMap(hp.Dataset.Modules),
                Item = item,
            };
            item.Display = ChildLabel(t);
            _childTargets[hp.Pid] = t;
            _childItems.Add(item);
            ChildTargetPanel.Visibility = Visibility.Visible;

            if (_childSelectedPid < 0)
                ChildTargetBox.SelectedItem = item; // fires OnChildTargetChanged -> SelectChildTarget
        }

        // Decoded records arrived for one followed process. Always fold them into
        // that target (bounded); if it's the one on screen, drive the live views.
        private void OnChildRecords(int pid, List<CallRecord> recs)
        {
            if (recs.Count == 0) return;
            if (!_childTargets.TryGetValue(pid, out var t)) return;

            t.TotalCalls += recs.Count;
            t.Records.AddRange(recs);
            TrimChildRecords(t);
            t.Item.Display = ChildLabel(t);

            if (!_childView || pid != _childSelectedPid) return;

            _captured.AddRange(recs);
            TrimCapturedToChild();
            CallList.AddRecords(recs);
            FunctionList.AddCounts(recs);
            FoldCallers(recs);

            if (!ReferenceEquals(_model.Records, _captured)) _model.UseLiveRecords(_captured);
            if (_captured.Count > 0)
            {
                int from = Math.Max(0, _captured.Count - 200);
                _model.SetActiveWindow(_captured[from].Time, _captured[_captured.Count - 1].Time + 1e-9);
                GraphView.RefreshActive();
            }
            StatusText.Text = $"Following · viewing pid {pid} ({t.Image}) · {t.TotalCalls} calls";
        }

        private void OnChildProcessExited(int pid)
        {
            if (!_childTargets.TryGetValue(pid, out var t)) return;
            t.Exited = true;
            t.Item.Display = ChildLabel(t);
            if (_childView && pid == _childSelectedPid)
                StatusText.Text = $"pid {pid} ({t.Image}) exited · {t.TotalCalls} calls — review retained.";
        }

        private void OnChildTargetChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (ChildTargetBox.SelectedItem is ChildTargetItem it) SelectChildTarget(it.Pid);
        }

        // Point the single-target views at one followed process's data. There is no
        // live session for a child (so the Memory tab is empty and caller frames
        // come from stack snapshots, as in offline review); everything driven by the
        // recorded calls — function list, graph, calls log, caller tree, timeline —
        // works from its dataset + records.
        private void SelectChildTarget(int pid)
        {
            if (!_childTargets.TryGetValue(pid, out var t)) return;
            _childSelectedPid = pid;
            _childView = true;

            // No _capture/_pollTimer for child-follow; the engine owns the polling.
            StopCaptureQuietly();
            _session?.Dispose();
            _session = null;
            _currentPe = null;
            _offlineTrace = false;
            _apiCaptureMode = false;
            _captureFocus = 0;
            _is64 = t.Is64;
            _moduleMap = t.ModuleMap;
            _liveDataset = t.Dataset;
            _selectedFunctionAddr = 0;

            _captured.Clear();
            _captured.AddRange(t.Records);
            _maxCursorSeen = 0;

            SetCallersTarget(0);
            _model.Load(t.Dataset);
            GraphView.SetModel(_model);
            PlayBar.SetData(t.Dataset);
            FunctionList.LoadFromDataset(t.Dataset);
            FunctionList.AddCounts(t.Records);
            DisposeFileMap();
            Hex.SetSource(null); // child targets have no live memory view

            CallList.Configure(_moduleMap);
            CallList.Clear();
            CallList.AddRecords(t.Records);
            ClearCallerGraph();
            EnsureCallerIndex();
            FoldCallers(t.Records);

            _model.UseLiveRecords(_captured);
            if (_captured.Count > 0)
            {
                int from = Math.Max(0, _captured.Count - 200);
                _model.SetActiveWindow(_captured[from].Time, _captured[_captured.Count - 1].Time + 1e-9);
                GraphView.RefreshActive();
            }

            StatusText.Text =
                $"Following · viewing pid {pid} ({t.Image}) · {t.TotalCalls} calls" +
                (t.Exited ? " · exited" : "") + " · click a function for its callers (snapshot depth).";
        }

        private static string ChildLabel(ChildTarget t) =>
            $"pid {t.Pid} · {t.Image} · {t.TotalCalls} call(s)" + (t.Exited ? " · exited" : "");

        // Bound a target's retained records so a busy/long-lived tree can't grow
        // host memory without limit; the running total still reflects everything.
        private void TrimChildRecords(ChildTarget t)
        {
            int over = t.Records.Count - ChildKeepLast;
            if (over > 0) t.Records.RemoveRange(0, over);
        }

        private void TrimCapturedToChild()
        {
            int over = _captured.Count - ChildKeepLast;
            if (over > 0) _captured.RemoveRange(0, over);
        }

        // Discover the main module's functions from the ON-DISK image, then rebase to
        // the actual (ASLR) load address. Scanning the file is reliable even while the
        // target is frozen at creation — where many of its pages aren't faulted in yet,
        // which makes a mapped scan badly under-read (e.g. Rufus: 8 found mapped vs
        // thousands from the file). Direct calls are relative (E8 rel32 / RIP-relative),
        // so relocation never rewrites them: the file's call targets, as RVAs, match the
        // running image exactly — only the load base differs, by <delta>, which we add back.
        private static (List<TracedFunction> Functions, List<(ulong Site, ulong Target)> Edges)
            DiscoverModuleSuspended(byte[] exeBytes, PeImage exe, ulong actualBase)
        {
            var arch = CpuArchitectures.For(exe.Is64Bit);
            var rawFuncs = new List<TracedFunction>();
            var rawEdges = new List<(ulong Site, ulong Target)>();
            CallSiteScanner.ScanFileImage(exeBytes, exe, arch, rawFuncs, rawEdges, maxEdges: 20000);

            ulong delta = unchecked(actualBase - exe.PreferredImageBase);
            var funcs = new List<TracedFunction>(rawFuncs.Count);
            foreach (var f in rawFuncs)
                funcs.Add(new TracedFunction(unchecked(f.Address + delta), actualBase, f.Name));
            var edges = new List<(ulong Site, ulong Target)>(rawEdges.Count);
            foreach (var (s, t) in rawEdges)
                edges.Add((unchecked(s + delta), unchecked(t + delta)));
            return (funcs, edges);
        }

        private static TraceDataset BuildUiDataset(
            string name, ulong imageBase, ulong size, string path,
            List<TracedFunction> funcs, List<(ulong Site, ulong Target)> edges)
        {
            var ds = new TraceDataset { TimeStart = 0, TimeEnd = 1 };
            ds.Modules.Add(new ModuleInfo(name, imageBase, size, path));
            ds.Functions.AddRange(funcs);
            int n = Math.Max(1, edges.Count);
            for (int i = 0; i < edges.Count; i++)
                ds.Records.Add(new CallRecord((double)i / n, edges[i].Site, edges[i].Target));
            return ds;
        }

        // Broad candidate set for a startup trace. Delegates to the shared
        // StartupPlan so the suspended-launch, DLL-load, and child-follow paths all
        // select the same way: order by inbound call sites, skip the hottest few,
        // and hold back leaf primitives (no-call utilities — char/string ops,
        // accessors — that get called in tight loops and flood the buffer), whether
        // they're tiny or just called from very many sites.
        // Notes in the diagnostics how many primitives were kept out of the limited
        // startup hook budget; the runtime auto-unhook backstops any that slip in.
        private List<ulong> BuildStartupCandidates(
            List<TracedFunction> funcs, List<(ulong Site, ulong Target)> edges, int skipTop, int max)
        {
            var heldBack = new List<ulong>();
            var list = StartupPlan.Candidates(funcs, edges, skipTop, max, deprioritized: heldBack);
            if (heldBack.Count > 0)
                _diag.Add($"held back {heldBack.Count} leaf primitive(s) from the startup set " +
                          "(tiny or high-fan-in no-call utilities that flood the buffer) — kept the higher-value functions.");
            return list;
        }

        // The static startup hook skip-list: RVAs (offsets from the main image base)
        // that the startup trace must NOT inline-hook, because their entry can't
        // tolerate a .text splice (e.g. a function the program reads/hashes as data, or
        // an awkward prologue). Found via the CDA_HOOK_RANGE bisection and recorded
        // here so everything else can be traced — no relaunch, no flood. Read fresh
        // each launch from cda_hook_skip.txt next to the exe / in the user profile /
        // in %TEMP%; one hex RVA per line (0x / +0x optional), '#' or '//' comments.
        private static string[] HookSkipFilePaths()
        {
            var list = new List<string>();
            void Try(Func<string> f) { try { list.Add(f()); } catch { } }
            Try(() => System.IO.Path.Combine(AppContext.BaseDirectory, "cda_hook_skip.txt"));
            Try(() => System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "cda_hook_skip.txt"));
            Try(() => System.IO.Path.Combine(System.IO.Path.GetTempPath(), "cda_hook_skip.txt"));
            return list.ToArray();
        }

        // Read + parse the skip-list: the UNION of RVAs across every candidate path, so
        // an RVA auto-appended to the canonical write file (below) is always honoured no
        // matter which other files exist. Returns the RVAs and a human-readable probe
        // (mirrors the range probe, so a run shows the skip-list took effect).
        private static (HashSet<ulong> Rvas, string Probe) ReadStartupSkipRvas()
        {
            var rvas = new HashSet<ulong>();
            var probed = new List<string>();
            foreach (var p in HookSkipFilePaths())
            {
                bool exists = false; string content = "";
                try { exists = System.IO.File.Exists(p); if (exists) content = System.IO.File.ReadAllText(p); }
                catch { }
                if (exists && content.Trim().Length > 0) ParseSkipRvas(content, rvas);
                probed.Add($"{p} [{(exists ? (content.Trim().Length == 0 ? "blank" : "found") : "absent")}]");
            }
            string probe = "hook-skip probe — " + string.Join(" | ", probed) + $" ; {rvas.Count} RVA(s) total";
            return (rvas, probe);
        }

        // The one canonical file the crash watch auto-appends culprits to: the
        // user-profile copy, which every build config reads (it's in the path list)
        // and which survives rebuilds (unlike a copy next to the exe).
        private static string SkipListWritePath() => System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "cda_hook_skip.txt");

        // Make sure the canonical skip-list file exists, recreating a template if it was
        // deleted, so it's always a real, discoverable, editable artifact. Returns its path.
        private static string EnsureSkipListExists()
        {
            string path = SkipListWritePath();
            try
            {
                if (!System.IO.File.Exists(path))
                    System.IO.File.WriteAllText(path,
                        "# CDA startup-trace hook skip-list.\n" +
                        "# RVAs (offsets from the main image base) the \"Launch & capture\" startup\n" +
                        "# trace must NOT inline-hook. One hex RVA per line (0x / +0x optional).\n" +
                        "# '#' or '//' starts a comment. Read fresh on every launch — edit freely.\n" +
                        "# Crashes that CDA can pin to a hook are auto-appended here.\n\n");
            }
            catch { }
            return path;
        }

        // Build the exclusion list automatically: append a crash culprit's RVA to the
        // skip-list so the NEXT launch skips it — without relaunching (the user decides
        // when to launch again). Returns the file written, or null if the RVA was already
        // listed or the write failed.
        private string? AppendToSkipList(ulong rva, string name)
        {
            try
            {
                if (ReadStartupSkipRvas().Rvas.Contains(rva)) return null; // already covered
                string path = SkipListWritePath();
                if (!System.IO.File.Exists(path) || new System.IO.FileInfo(path).Length == 0)
                    System.IO.File.WriteAllText(path,
                        "# CDA startup-trace hook skip-list — RVAs (from the image base) NOT to inline-hook.\n" +
                        "# Auto-appended on crashes; edit freely. One hex RVA per line.\n\n");
                string note = name.Replace('\n', ' ').Replace('\r', ' ');
                System.IO.File.AppendAllText(path, $"0x{rva:X}   # {note} — auto-added after a crash\n");
                return path;
            }
            catch (Exception ex) { _diag.Add("skip-list: couldn't write — " + ex.Message); return null; }
        }

        private static void ParseSkipRvas(string content, HashSet<ulong> rvas)
        {
            foreach (var rawLine in content.Replace("\r", "").Split('\n'))
            {
                string line = rawLine.Trim();
                int comment = line.IndexOf('#'); if (comment >= 0) line = line.Substring(0, comment);
                comment = line.IndexOf("//", StringComparison.Ordinal); if (comment >= 0) line = line.Substring(0, comment);
                line = line.Trim().TrimStart('+');
                if (line.Length == 0) continue;
                if (line.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) line = line.Substring(2);
                if (ulong.TryParse(line, System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture, out ulong rva))
                    rvas.Add(rva);
            }
        }

        // Order discovered functions so the most-targeted (most likely to actually
        // be called at runtime) come first, but skip the very top few — those tend
        // to be tiny runtime primitives that are riskier to hook and less useful.
        private static List<ulong> BuildAutoCandidates(TraceDataset data)
        {
            var freq = new Dictionary<ulong, int>();
            foreach (var rec in data.Records)
                freq[rec.Destination] = freq.TryGetValue(rec.Destination, out int c) ? c + 1 : 1;

            var ordered = new List<TracedFunction>(data.Functions);
            ordered.Sort((a, b) =>
            {
                int fb = freq.TryGetValue(b.Address, out int y) ? y : 0;
                int fa = freq.TryGetValue(a.Address, out int x) ? x : 0;
                return fb.CompareTo(fa);
            });

            var candidates = new List<ulong>();
            int skipTop = ordered.Count > 12 ? 3 : 0;
            for (int i = skipTop; i < ordered.Count && candidates.Count < 60; i++)
                candidates.Add(ordered[i].Address);
            if (candidates.Count == 0)
                foreach (var f in ordered) candidates.Add(f.Address);
            return candidates;
        }

        private void OnStartCapture(object sender, RoutedEventArgs e)
        {
            if (_session == null || _liveDataset == null)
            {
                StatusText.Text = "Attach to a process first (Attach to process…), then start capture.";
                return;
            }
            if (_capture != null) { StatusText.Text = "Capture already running — stop it first."; return; }

            // A 32-bit host cannot write code a 64-bit target will run. (An x64
            // host can instrument both x64 and WOW64 x86 targets.)
            if (!Environment.Is64BitProcess && _session.Is64Bit)
            {
                StatusText.Text = "A 32-bit build cannot instrument a 64-bit target. Rebuild as x64.";
                return;
            }

            StartLiveCapture();
        }

        // Instruments ONLY the function currently selected in the list.
        private void StartLiveCapture()
        {
            if (_session == null || _liveDataset == null) return;

            bool valid = _selectedFunctionAddr != 0 &&
                         _liveDataset.Functions.Exists(f => f.Address == _selectedFunctionAddr);
            if (!valid)
            {
                StatusText.Text = "Select a function on the left first, then Start capture.";
                return;
            }

            StartCaptureOn(new List<ulong> { _selectedFunctionAddr }, $"0x{_selectedFunctionAddr:X}", preserveLog: true);
        }

        // --- capture Windows API calls only ----------------------------------

        // Hook the Windows API functions the attached process imports (kernel32,
        // user32, ntdll, …) and record every call to them. Discovery reads the
        // app modules' import tables and resolves each bound IAT slot to the real
        // entry; see ApiImportScanner. Mirrors OnStartCapture's preconditions.
        private async void OnCaptureApi(object sender, RoutedEventArgs e)
        {
            if (_session == null)
            {
                StatusText.Text = "Attach to a process first (Attach to process…), then Capture Windows API.";
                return;
            }
            if (_capture != null || _dllCapture != null)
            {
                StatusText.Text = "Capture already running — stop it first.";
                return;
            }
            if (!Environment.Is64BitProcess && _session.Is64Bit)
            {
                StatusText.Text = "A 32-bit build cannot instrument a 64-bit target. Rebuild as x64.";
                return;
            }

            _offlineTrace = false;
            _childView = false;
            var session = _session;
            Diag("Windows API: discovering imported APIs…");

            ApiImportScanner.Result api;
            try
            {
                // Reads target memory + parses PE import tables off the UI thread.
                api = await Task.Run(() => ApiImportScanner.Discover(session.Process, session.Modules));
            }
            catch (Exception ex)
            {
                Diag("API discovery failed: " + ex.Message);
                return;
            }

            // The session could have been torn down while we were scanning.
            if (_session != session) { Diag("target changed during API discovery — aborted."); return; }

            if (api.Functions.Count == 0)
            {
                Diag("No Windows API imports found to hook — the target may be managed (.NET), packed, " +
                     "or a thin launcher that loads its libraries later. Try Launch & capture, or attach " +
                     "after it has loaded its DLLs.");
                return;
            }

            // Bound the hooked set (and how long the target stays frozen). The list
            // shows exactly what we hook, so trim the dataset to match.
            bool trimmed = api.Functions.Count > ApiTraceFunctions;
            if (trimmed) api.Functions.RemoveRange(ApiTraceFunctions, api.Functions.Count - ApiTraceFunctions);

            var addresses = new List<ulong>(api.Functions.Count);
            foreach (var f in api.Functions) addresses.Add(f.Address);

            // Build the API-only view: nodes are the imported APIs, grouped under
            // the system DLLs they live in. Records arrive live from the capture.
            var ds = new TraceDataset { TimeStart = 0, TimeEnd = 1 };
            ds.Modules.AddRange(api.ApiModules);
            ds.Functions.AddRange(api.Functions);

            _currentPe = null;
            _is64 = session.Is64Bit;
            _liveDataset = ds;
            _moduleMap = session.Modules; // full map: resolves both callers (app) and callees (OS)
            _selectedFunctionAddr = 0;
            _captureFocus = 0;

            _model.Load(ds);
            GraphView.SetModel(_model);
            PlayBar.SetData(ds);
            FunctionList.LoadFromDataset(ds);
            SetCallersTarget(0);

            _diag.Add($"API discovery: {api.Functions.Count} entr{(api.Functions.Count == 1 ? "y" : "ies")} " +
                      $"across {api.ApiModules.Count} system module(s), from {api.ScannedModules.Count} app module(s)" +
                      (api.ExcludedHot > 0 ? $"; skipped {api.ExcludedHot} hot primitive(s) (critical-section/heap/last-error)" : "") +
                      (api.SkippedLargeModules > 0 ? $"; skipped {api.SkippedLargeModules} oversized module(s)" : "") +
                      (trimmed ? $"; capped to the first {ApiTraceFunctions} (alphabetical)" : ""));

            // Arm the hooks (resets the call log; starts polling). maxFunctions is
            // the cap; the ring is sized for a broad trace so hot APIs don't lap it.
            StartCaptureOn(addresses, $"{addresses.Count} Windows API function(s)",
                maxFunctions: ApiTraceFunctions, bufferRecords: StartupBufferRecords);
            _apiCaptureMode = _capture != null; // a click now inspects callers, doesn't refocus
        }

        // Hook the IAT slots of the imports the attached process makes into the OS
        // — by overwriting import-table pointers (data), NEVER patching .text. This
        // captures the same Windows-API call flow as Capture Windows API, but works
        // on targets that checksum their own code and self-terminate when patched
        // (the unhandled-int3 / anti-tamper case). Mirrors OnCaptureApi otherwise.
        private async void OnCaptureIat(object sender, RoutedEventArgs e)
        {
            if (_session == null)
            {
                StatusText.Text = "Attach to a process first (Attach to process…), then Capture imports (IAT).";
                return;
            }
            if (_capture != null || _dllCapture != null)
            {
                StatusText.Text = "Capture already running — stop it first.";
                return;
            }
            if (!Environment.Is64BitProcess && _session.Is64Bit)
            {
                StatusText.Text = "A 32-bit build cannot instrument a 64-bit target. Rebuild as x64.";
                return;
            }

            _offlineTrace = false;
            _childView = false;
            var session = _session;
            Diag("IAT: discovering imported APIs (import-table slots)…");

            ApiImportScanner.SlotResult slots;
            try
            {
                slots = await Task.Run(() => ApiImportScanner.DiscoverImportSlots(session.Process, session.Modules));
            }
            catch (Exception ex)
            {
                Diag("IAT discovery failed: " + ex.Message);
                return;
            }

            if (_session != session) { Diag("target changed during IAT discovery — aborted."); return; }

            if (slots.Slots.Count == 0)
            {
                Diag("No import slots found to hook — the target may be managed (.NET), packed, or a thin " +
                     "launcher that loads its libraries later. Try attaching after it has loaded its DLLs.");
                return;
            }

            // Bound the hooked set; the list shows exactly what we hook, so trim to match.
            bool trimmed = slots.Slots.Count > ApiTraceFunctions;
            if (trimmed) slots.Slots.RemoveRange(ApiTraceFunctions, slots.Slots.Count - ApiTraceFunctions);

            // Distinct resolved callees → a TracedFunction each, for labels/views.
            var funcs = new List<TracedFunction>();
            var seen = new HashSet<ulong>();
            foreach (var s in slots.Slots)
                if (seen.Add(s.Target)) funcs.Add(new TracedFunction(s.Target, s.OwnerBase, s.Label));

            var ds = new TraceDataset { TimeStart = 0, TimeEnd = 1 };
            ds.Modules.AddRange(slots.ApiModules);
            ds.Functions.AddRange(funcs);

            _currentPe = null;
            _is64 = session.Is64Bit;
            _liveDataset = ds;
            _moduleMap = session.Modules; // resolves both callers (app) and callees (OS)
            _selectedFunctionAddr = 0;
            _captureFocus = 0;

            _model.Load(ds);
            GraphView.SetModel(_model);
            PlayBar.SetData(ds);
            FunctionList.LoadFromDataset(ds);
            SetCallersTarget(0);

            _diag.Add($"IAT discovery: {slots.Slots.Count} slot(s) over {funcs.Count} distinct API(s) " +
                      $"across {slots.ApiModules.Count} system module(s), from {slots.ScannedModules.Count} app module(s)" +
                      (slots.ExcludedHot > 0 ? $"; skipped {slots.ExcludedHot} hot primitive(s)" : "") +
                      (slots.SkippedLargeModules > 0 ? $"; skipped {slots.SkippedLargeModules} oversized module(s)" : "") +
                      (trimmed ? $"; capped to the first {ApiTraceFunctions} (alphabetical)" : ""));

            var imports = new List<(ulong Slot, ulong Target)>(slots.Slots.Count);
            foreach (var s in slots.Slots) imports.Add((s.SlotVa, s.Target));

            StartIatCaptureOn(imports, $"{imports.Count} import slot(s)");
        }

        // Arm an IAT capture over the given (slot, target) pairs and start polling.
        // Mirrors StartCaptureOn but routes through CaptureSession.StartIat, which
        // overwrites import pointers instead of splicing code — so nothing is
        // written to the target's .text.
        private void StartIatCaptureOn(List<(ulong Slot, ulong Target)> imports, string label)
        {
            if (_session == null || imports.Count == 0) return;
            if (!_session.Process.IsAlive)
            {
                Diag($"couldn't start IAT capture on {label} — target process has exited.");
                if (StatusText != null) StatusText.Text = "Target process has exited.";
                return;
            }

            _maxCursorSeen = 0;
            try
            {
                _capture = CaptureSession.StartIat(_session.Process.Pid, imports,
                    maxFunctions: ApiTraceFunctions, bufferRecords: StartupBufferRecords,
                    out int instrumented, out int skipped, out string? firstError);
                CallList.Configure(_moduleMap);
                _captured.Clear();
                CallList.Clear();
                ClearCallerGraph();
                _autoUnhooked.Clear();
                _diag.Add($"IAT capture.Start({imports.Count} slot(s)): instrumented={instrumented} skipped={skipped} firstError={firstError ?? "(none)"}");

                if (instrumented == 0)
                {
                    _capture?.Dispose();
                    _capture = null;
                    Diag($"couldn't start IAT capture on {label} — {firstError ?? "no slot could be hooked."}");
                    return;
                }

                _pollTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
                _pollTimer.Tick += OnPollTick;
                _pollTimer.Start();
                _captureFocus = 0;
                _apiCaptureMode = true; // broad trace: a click inspects callers, doesn't refocus

                Diag($"capturing {label} · {instrumented} IAT hook(s) installed · 0 calls yet");
            }
            catch (Exception ex)
            {
                string why = _session.Process.IsAlive ? ex.Message : "target process has exited.";
                Diag("start IAT capture failed: " + why);
                _capture?.Dispose();
                _capture = null;
            }
        }

        // --- capture via CPU debug registers (hardware breakpoints) ----------

        // Trace the selected function by setting a hardware execution breakpoint on
        // its entry across every thread — writing NOTHING to the target's memory.
        // This is the one mode that captures a binary which both checksums its own
        // code AND can't be IAT-hooked: nothing is patched, so there's nothing to
        // detect. It needs a debugger attach (so an anti-DEBUG target may notice)
        // and can watch at most four addresses at once (four debug registers); v1
        // watches the one selected function. x64 targets only.
        private void OnCaptureHwbp(object sender, RoutedEventArgs e)
        {
            if (_session == null || _liveDataset == null)
            {
                StatusText.Text = "Attach to a process first (Attach to process…), then select a function and Capture (hardware bp).";
                return;
            }
            if (_capture != null || _dllCapture != null || _childFollow != null || _hwbp != null)
            {
                StatusText.Text = "Capture already running — stop it first.";
                return;
            }
            if (!Environment.Is64BitProcess || !_session.Is64Bit)
            {
                StatusText.Text = "Hardware-breakpoint capture currently supports x64 targets only.";
                return;
            }

            bool valid = _selectedFunctionAddr != 0 &&
                         _liveDataset.Functions.Exists(f => f.Address == _selectedFunctionAddr);
            if (!valid)
            {
                StatusText.Text = "Select a function on the left first, then Capture (hardware bp).";
                return;
            }
            if (!_session.Process.IsAlive)
            {
                StatusText.Text = "Target process has exited.";
                return;
            }

            _offlineTrace = false;
            _childView = false;
            _apiCaptureMode = false;
            _captureFocus = _selectedFunctionAddr;
            _maxCursorSeen = 0;

            // Reset the live views to the attached dataset (so labels/the graph
            // resolve), clear any prior records, then stream hits in.
            _captured.Clear();
            CallList.Configure(_moduleMap);
            CallList.Clear();
            ClearCallerGraph();
            _autoUnhooked.Clear();
            _model.Load(_liveDataset);
            GraphView.SetModel(_model);
            GraphView.SetSelected(_selectedFunctionAddr);
            PlayBar.SetData(_liveDataset);

            var hb = new HwBreakpointCapture(_session.Process.Pid, new List<ulong> { _selectedFunctionAddr });
            hb.Log += m => Dispatcher.BeginInvoke(new Action(() => Diag(m)));
            hb.RecordsCaptured += recs => Dispatcher.BeginInvoke(new Action(() => ApplyHwRecords(recs)));
            hb.TargetExited += () => Dispatcher.BeginInvoke(new Action(() =>
            {
                Diag("hardware bp: target exited or detached — capture stopped.");
                StopHwbp();
            }));
            _hwbp = hb;

            Diag($"hardware bp: watching 0x{_selectedFunctionAddr:X} via a CPU debug register (no memory modified). " +
                 "Attaching as a debugger — if the target also anti-debugs, it may notice.");
            hb.Start();
            UpdateClearCallsState();
            StatusText.Text = $"Capturing (hardware bp) · 0x{_selectedFunctionAddr:X} · 0 calls";
        }

        // Apply a batch of hardware-breakpoint records to the live views (mirrors
        // the single-target half of OnChildRecords; HW capture has no CaptureSession
        // and no poll — records are pushed from the debug loop).
        private void ApplyHwRecords(List<CallRecord> recs)
        {
            if (recs.Count == 0 || _hwbp == null) return;

            _captured.AddRange(recs);
            CallList.AddRecords(recs);
            FunctionList.AddCounts(recs);
            FoldCallers(recs);

            if (!ReferenceEquals(_model.Records, _captured)) _model.UseLiveRecords(_captured);
            if (_captured.Count > 0)
            {
                int from = Math.Max(0, _captured.Count - 200);
                _model.SetActiveWindow(_captured[from].Time, _captured[_captured.Count - 1].Time + 1e-9);
                GraphView.RefreshActive();
            }
            StatusText.Text = $"Capturing (hardware bp) · {_hwbp.BreakpointCount} breakpoint(s) · {_captured.Count} calls";
        }

        private void StopHwbp()
        {
            if (_hwbp != null) { _hwbp.Stop(); _hwbp = null; }
            UpdateClearCallsState();
        }

        // --- "Called by" tree (B) and per-call "Call stack" (A) ----------------

        // Select the function whose caller tree to show (B). The reverse-edge map
        // is global — folded from every captured call's local stack chain — so the
        // tree recurses past the depth of any single snapshot by composing edges
        // across records. destination == 0 clears the panels.
        private void SetCallersTarget(ulong destination)
        {
            _callersFor = destination;
            if (destination == 0 || _liveDataset == null)
            {
                _appModuleCache.Clear();
                _retAddrCache.Clear();
                ClearCallerGraph();
                Callers.Clear();
                CallStack.Clear();
                return;
            }
            EnsureCallerIndex();
            RefreshCallersView();
        }

        // Fold new captured records into the GLOBAL reverse-edge map — every call,
        // not just the selected function's, because the tree needs callers-of-
        // callers. Update the header counts live, but DON'T rebuild the tree every
        // poll — that would flicker and collapse the user's expansions; the tree is
        // (re)built on selection and when capture stops.
        private void FoldCallers(IReadOnlyList<CallRecord> recs)
        {
            if (recs.Count == 0) return;
            EnsureCallerIndex();
            foreach (var r in recs) FoldOne(r);
            if (_callersFor != 0) UpdateCallersHeader();
        }

        // Fold caller chains that were already resolved on the poll worker into the
        // global reverse-edge map. Same effect as FoldCallers -> FoldOne, but the
        // expensive chain extraction happened off the UI thread, so this is only
        // dictionary updates. recs[i] pairs with chains[i].
        private void FoldCallersPrecomputed(List<CallRecord> recs, List<List<(ulong Addr, string Name)>> chains)
        {
            if (recs.Count == 0) return;
            EnsureCallerIndex();
            for (int i = 0; i < recs.Count; i++)
            {
                var rec = recs[i];
                _calleeTotals[rec.Destination] = _calleeTotals.TryGetValue(rec.Destination, out long t) ? t + 1 : 1;
                if (!_fnNames.ContainsKey(rec.Destination)) _fnNames[rec.Destination] = CallerTitleFor(rec.Destination);

                var chain = chains[i];
                if (chain.Count == 0) continue;
                AddEdge(rec.Destination, chain[0].Addr);
                _fnNames[chain[0].Addr] = chain[0].Name;
                for (int j = 1; j < chain.Count; j++)
                {
                    AddEdge(chain[j - 1].Addr, chain[j].Addr);
                    _fnNames[chain[j].Addr] = chain[j].Name;
                }
            }
            if (_callersFor != 0) UpdateCallersHeader();
        }

        // Adaptive auto-unhook: remove a hooked callee that is flooding the ring
        // (forcing record loss and drowning out everything else) so the rest of the
        // trace keeps recording; the function stays in the views with the count it
        // reached. Two complementary triggers:
        //   (1) cumulative ceiling — any callee seen this batch whose TOTAL calls have
        //       crossed RunawayCeilingCalls, regardless of how its calls are spread
        //       over time. Runs every tick (any batch size); this is what catches a
        //       DIFFUSE runaway that never dominates a single batch.
        //   (2) per-batch dominance — a single callee both dominating a heavy batch
        //       and past the lower RunawayMinCalls floor; catches a BURSTY runaway
        //       early, before it reaches the ceiling.
        // Never touches a user-focused single-function capture, and runs on the UI
        // thread only after a poll completes (no Poll is in flight), so the brief
        // thread-freeze for the byte-restore can't race the worker's reads.
        private void CheckRunaway(List<CallRecord> recs, CaptureSession cap)
        {
            if (_captureFocus != 0) return; // user asked for exactly this function
            if (recs.Count == 0) return;

            // Per-callee counts in this batch (and the single most frequent).
            ulong top = 0;
            int topCount = 0;
            var counts = new Dictionary<ulong, int>();
            foreach (var r in recs)
            {
                int c = counts.TryGetValue(r.Destination, out int v) ? v + 1 : 1;
                counts[r.Destination] = c;
                if (c > topCount) { topCount = c; top = r.Destination; }
            }

            // (1) Cumulative-ceiling trigger: unhook every distinct callee in this
            // batch whose cumulative total has crossed the hard ceiling.
            foreach (var kv in counts)
            {
                ulong fn = kv.Key;
                if (_autoUnhooked.Contains(fn)) continue;
                if (_calleeTotals.TryGetValue(fn, out long t) && t >= RunawayCeilingCalls)
                    TryAutoUnhook(cap, fn, t);
            }

            // (2) Per-batch dominance trigger (heavy batches only). If the top callee
            // crossed the ceiling above it's already in _autoUnhooked and skipped.
            if (recs.Count >= RunawayBatchMin && top != 0 && !_autoUnhooked.Contains(top)
                && topCount >= recs.Count * RunawayBatchShare
                && _calleeTotals.TryGetValue(top, out long total) && total >= RunawayMinCalls)
            {
                TryAutoUnhook(cap, top, total);
            }
        }

        // Remove one hooked callee and note it. Returns nothing; UnhookFunction is
        // the only mutation and it's idempotent per address via _autoUnhooked.
        private void TryAutoUnhook(CaptureSession cap, ulong fn, long total)
        {
            if (!cap.UnhookFunction(fn)) return;
            _autoUnhooked.Add(fn);
            string nm = _fnNames.TryGetValue(fn, out var n) ? n : DescribeAddr(fn);
            _diag.Add($"auto-unhooked runaway {nm} after ~{total:N0} call(s) — it was flooding the buffer; " +
                      $"{cap.HookedCount} hook(s) still recording.");
        }

        // Build/refresh the worker-side chain resolver when the live session or its
        // module map changes. Cheap: snapshots the read handle, module map, and the
        // (immutable, replaced-not-mutated) function-entry index. The resolver shares
        // only read-only / concurrently-safe state with the UI and owns its own
        // unwinder + caches, so the poll worker can use it without touching UI state.
        private void EnsureChainResolver()
        {
            if (_session == null || _moduleMap == null)
            {
                _chainResolver = null;
                _chainResolverSession = null;
                _chainResolverMap = null;
                return;
            }
            if (_chainResolver != null
                && ReferenceEquals(_chainResolverSession, _session)
                && ReferenceEquals(_chainResolverMap, _moduleMap))
                return;
            EnsureCallerIndex();
            _chainResolver = new CaptureChainResolver(_session.Process, _moduleMap, _idxAddr, _idxName, _is64, WinDir());
            _chainResolverSession = _session;
            _chainResolverMap = _moduleMap;
        }

        // One poll's decoded records and (optionally) their pre-resolved caller
        // chains, produced together on the worker thread. Chains is null when no
        // resolver was available, in which case the UI folds via FoldCallers.
        private sealed class PolledBatch
        {
            public List<CallRecord> Records = new();
            public List<List<(ulong Addr, string Name)>>? Chains;
        }

        // Self-contained, worker-thread caller-chain resolver. Holds only read-only /
        // concurrently-safe references shared with the UI (the target read handle and
        // the immutable module map) plus its OWN unwinder, caches, and a snapshot of
        // the function-entry index — so the poll worker can extract each record's
        // caller chain (the expensive stack unwinding + return-address probes)
        // without touching any UI-thread state. Mirrors the UI's ExtractLocalChain.
        // Only one batch is resolved at a time (serialized by the poll guard), so the
        // mutable caches here are only ever touched by a single thread.
        private sealed class CaptureChainResolver
        {
            private readonly TargetProcess _proc;
            private readonly ModuleMap _modules;
            private readonly ulong[] _idxAddr;
            private readonly string[] _idxName;
            private readonly bool _is64;
            private readonly string _winDir;
            private readonly StackUnwinder _unwinder;
            private readonly Dictionary<ulong, bool> _appModuleCache = new();
            private readonly Dictionary<ulong, bool> _retAddrCache = new();

            public CaptureChainResolver(TargetProcess proc, ModuleMap modules,
                ulong[] idxAddr, string[] idxName, bool is64, string winDir)
            {
                _proc = proc;
                _modules = modules;
                _idxAddr = idxAddr;
                _idxName = idxName;
                _is64 = is64;
                _winDir = winDir ?? "";
                _unwinder = new StackUnwinder(proc, modules);
            }

            public List<List<(ulong Addr, string Name)>> ResolveAll(List<CallRecord> recs)
            {
                var all = new List<List<(ulong Addr, string Name)>>(recs.Count);
                for (int i = 0; i < recs.Count; i++) all.Add(Resolve(recs[i]));
                return all;
            }

            // Heuristic word-scan plus exact x64 .pdata unwinding, keeping whichever
            // reaches further (matches MainWindow.ExtractLocalChain).
            private List<(ulong Addr, string Name)> Resolve(CallRecord rec)
            {
                var heuristic = Heuristic(rec);
                if (_is64 && rec.StackSnapshot != null && rec.StackSnapshot.Length > 0)
                {
                    var raw = _unwinder.Unwind(rec.StackPointer, rec.StackSnapshot, LooksLikeReturnAddress);
                    var precise = FromReturnAddresses(raw);
                    if (precise.Count > heuristic.Count) return precise;
                }
                return heuristic;
            }

            private List<(ulong Addr, string Name)> Heuristic(CallRecord rec)
            {
                var chain = new List<(ulong Addr, string Name)>();
                var snap = rec.StackSnapshot;
                ulong last = 0;
                bool first = true;
                for (int i = 0; i < snap.Length; i++)
                {
                    ulong w = snap[i];
                    if (!IsAppCode(w)) continue;
                    if (i > 0 && !LooksLikeReturnAddress(w)) continue;
                    ToFunction(w, out ulong fn, out string nm);
                    if (!first && fn == last) continue;
                    first = false;
                    last = fn;
                    chain.Add((fn, nm));
                }
                return chain;
            }

            private List<(ulong Addr, string Name)> FromReturnAddresses(List<ulong> ras)
            {
                var chain = new List<(ulong Addr, string Name)>();
                ulong last = 0;
                bool first = true;
                foreach (ulong w in ras)
                {
                    if (!IsAppCode(w)) continue;
                    ToFunction(w, out ulong fn, out string nm);
                    if (!first && fn == last) continue;
                    first = false;
                    last = fn;
                    chain.Add((fn, nm));
                }
                return chain;
            }

            private bool IsAppCode(ulong addr)
            {
                var m = _modules.Resolve(addr);
                if (m == null) return false;
                if (_appModuleCache.TryGetValue(m.BaseAddress, out bool app)) return app;
                app = _winDir.Length == 0 || string.IsNullOrEmpty(m.Path) ||
                      !m.Path!.StartsWith(_winDir, StringComparison.OrdinalIgnoreCase);
                _appModuleCache[m.BaseAddress] = app;
                return app;
            }

            private bool LooksLikeReturnAddress(ulong addr)
            {
                if (_retAddrCache.TryGetValue(addr, out bool ok)) return ok;
                ok = false;
                if (addr > 8)
                {
                    byte[] b = new byte[8];
                    if (_proc.ReadMemory(addr - 8, b) == 8)
                    {
                        if (b[3] == 0xE8) ok = true;
                        else
                            for (int p = 0; p <= 6 && !ok; p++)
                                if (b[p] == 0xFF && ((b[p + 1] >> 3) & 7) == 2) ok = true;
                    }
                }
                _retAddrCache[addr] = ok;
                return ok;
            }

            private void ToFunction(ulong addr, out ulong key, out string name)
            {
                if (FloorToFunction(addr, out ulong fn, out string fname)) { key = fn; name = fname; }
                else { key = addr; name = _modules.Describe(addr); }
            }

            private bool FloorToFunction(ulong addr, out ulong fn, out string name)
            {
                fn = 0; name = "";
                if (_idxAddr.Length == 0) return false;
                int lo = Array.BinarySearch(_idxAddr, addr);
                if (lo < 0) lo = ~lo - 1;
                if (lo < 0 || lo >= _idxAddr.Length) return false;
                if (!SameModule(_idxAddr[lo], addr)) return false;
                fn = _idxAddr[lo];
                name = _idxName[lo];
                return true;
            }

            private bool SameModule(ulong a, ulong b)
            {
                var ma = _modules.Resolve(a);
                var mb = _modules.Resolve(b);
                return ma != null && mb != null && ma.BaseAddress == mb.BaseAddress;
            }
        }

        // Fold one call: add reverse edges callee<-frame0, frame0<-frame1, … from
        // its local stack chain, so the global graph composes across records.
        private void FoldOne(CallRecord rec)
        {
            _calleeTotals[rec.Destination] = _calleeTotals.TryGetValue(rec.Destination, out long t) ? t + 1 : 1;
            if (!_fnNames.ContainsKey(rec.Destination)) _fnNames[rec.Destination] = CallerTitleFor(rec.Destination);

            var chain = ExtractLocalChain(rec);
            if (chain.Count == 0) return;

            AddEdge(rec.Destination, chain[0].Addr);
            _fnNames[chain[0].Addr] = chain[0].Name;
            for (int i = 1; i < chain.Count; i++)
            {
                AddEdge(chain[i - 1].Addr, chain[i].Addr);
                _fnNames[chain[i].Addr] = chain[i].Name;
            }
        }

        private void AddEdge(ulong callee, ulong caller)
        {
            if (caller == callee) return; // a single frame can't be its own caller
            if (!_callerEdges.TryGetValue(callee, out var callers))
                _callerEdges[callee] = callers = new Dictionary<ulong, long>();
            callers[caller] = callers.TryGetValue(caller, out long c) ? c + 1 : 1;
        }

        // Extract the program's own call chain for one record from its stack
        // snapshot: nearest local caller first, outward toward the entry point.
        // Runtime/CRT frames in system DLLs are skipped; each return address is
        // floored to its enclosing function and consecutive duplicates collapsed.
        // Shared by the per-call "Call stack" view (A) and the caller-tree fold (B).
        private List<(ulong Addr, string Name)> ExtractLocalChain(CallRecord rec)
        {
            var heuristic = ExtractLocalChainHeuristic(rec);

            // x64 live target: exact .pdata unwinding walks through runtime frames
            // and can reach app callers the word scan misses. Each frame is
            // validated (resolves to a module + looks like a real return site), and
            // we keep whichever chain reaches further — so this only matches or
            // improves on the heuristic, never regresses.
            if (_is64 && _session != null && rec.StackSnapshot != null && rec.StackSnapshot.Length > 0)
            {
                EnsureUnwinder();
                if (_unwinder != null)
                {
                    var raw = _unwinder.Unwind(rec.StackPointer, rec.StackSnapshot, LooksLikeReturnAddress);
                    var precise = ChainFromReturnAddresses(raw);
                    if (precise.Count > heuristic.Count) return precise;
                }
            }
            return heuristic;
        }

        // Create / refresh the unwinder for the current live x64 session.
        private void EnsureUnwinder()
        {
            if (!_is64 || _session == null) { _unwinder = null; _unwinderFor = null; return; }
            if (_unwinder != null && ReferenceEquals(_unwinderFor, _session)) return;
            _unwinder = new StackUnwinder(_session.Process, _session.Modules);
            _unwinderFor = _session;
        }

        // Turn a raw return-address chain (from the unwinder) into the program's
        // own caller chain: skip runtime/system frames, floor each to its enclosing
        // function, and collapse consecutive duplicates — the same shaping the
        // heuristic applies to the words it accepts.
        private List<(ulong Addr, string Name)> ChainFromReturnAddresses(List<ulong> returnAddresses)
        {
            var chain = new List<(ulong Addr, string Name)>();
            ulong last = 0;
            bool first = true;
            foreach (ulong w in returnAddresses)
            {
                if (!IsAppCode(w)) continue;
                ToFunction(w, out ulong fn, out string nm);
                if (!first && fn == last) continue;
                first = false;
                last = fn;
                chain.Add((fn, nm));
            }
            return chain;
        }

        // Word-scan fallback: accept stack words that look like app-code return
        // addresses. The literal return address (i == 0) is trusted; deeper words
        // must look like real return addresses so data isn't mistaken for frames.
        private List<(ulong Addr, string Name)> ExtractLocalChainHeuristic(CallRecord rec)
        {
            var chain = new List<(ulong Addr, string Name)>();
            var snap = rec.StackSnapshot;
            ulong last = 0;
            bool first = true;
            for (int i = 0; i < snap.Length; i++)
            {
                ulong w = snap[i];
                if (!IsAppCode(w)) continue;
                if (i > 0 && !LooksLikeReturnAddress(w)) continue;
                ToFunction(w, out ulong fn, out string nm);
                if (!first && fn == last) continue; // collapse repeats within one function
                first = false;
                last = fn;
                chain.Add((fn, nm));
            }
            return chain;
        }

        // Per-call "Call stack" (A): one captured call's local chain, innermost
        // (nearest the callee) first. Populated when a call is clicked in Calls.
        private void ShowCallStack(CallRecord rec)
        {
            var chain = ExtractLocalChain(rec);
            var frames = new List<CallStackView.Frame>(chain.Count);
            for (int i = 0; i < chain.Count; i++)
                frames.Add(new CallStackView.Frame
                {
                    Address = chain[i].Addr,
                    Depth = i.ToString(),
                    Function = chain[i].Name,
                    Module = _moduleMap?.Resolve(chain[i].Addr)?.Name ?? "",
                });
            CallStack.Show($"{CallerTitleFor(rec.Destination)}  (t={rec.Time:0.000000}s)", frames);
        }

        // Drop the whole caller graph + index (new capture / context switch).
        private void ClearCallerGraph()
        {
            _callerEdges.Clear();
            _calleeTotals.Clear();
            _fnNames.Clear();
            _callerIndexFor = null;
            _idxAddr = Array.Empty<ulong>();
            _idxName = Array.Empty<string>();
        }

        // Build the function-entry index lazily, once per dataset, so folds during
        // capture can floor return addresses. Auto-invalidates when the live
        // dataset changes.
        private void EnsureCallerIndex()
        {
            if (!ReferenceEquals(_callerIndexFor, _liveDataset))
            {
                RebuildCallerIndex();
                _callerIndexFor = _liveDataset;
            }
        }

        // Floor an app address to its enclosing discovered function (same module),
        // else fall back to module+offset.
        private void ToFunction(ulong addr, out ulong key, out string name)
        {
            if (FloorToFunction(addr, out ulong fn, out string fname)) { key = fn; name = fname; }
            else { key = addr; name = DescribeAddr(addr); }
        }

        private bool FloorToFunction(ulong addr, out ulong fn, out string name)
        {
            fn = 0; name = "";
            if (_idxAddr.Length == 0) return false;
            int lo = Array.BinarySearch(_idxAddr, addr);
            if (lo < 0) lo = ~lo - 1;
            if (lo < 0 || lo >= _idxAddr.Length) return false;
            if (!SameModule(_idxAddr[lo], addr)) return false;
            fn = _idxAddr[lo];
            name = _idxName[lo];
            return true;
        }

        // True if <addr> lies in one of the program's own (non-Windows) modules.
        // Code outside any known module is NOT treated as app code (it might be a
        // JIT/dynamic region, not a stable caller label).
        private bool IsAppCode(ulong addr)
        {
            if (_moduleMap == null) return false;
            var m = _moduleMap.Resolve(addr);
            if (m == null) return false;
            if (_appModuleCache.TryGetValue(m.BaseAddress, out bool app)) return app;
            string wd = WinDir();
            app = wd.Length == 0 || string.IsNullOrEmpty(m.Path) ||
                  !m.Path!.StartsWith(wd, StringComparison.OrdinalIgnoreCase);
            _appModuleCache[m.BaseAddress] = app;
            return app;
        }

        // Heuristic validation that <addr> is a real return address: the bytes just
        // before it should be a CALL. Reads code from the target (stable, unlike the
        // stack) and caches the result. Filters stray app-code-looking data words on
        // the captured stack from being mistaken for frames.
        private bool LooksLikeReturnAddress(ulong addr)
        {
            if (_retAddrCache.TryGetValue(addr, out bool ok)) return ok;
            ok = false;
            var proc = _session?.Process;
            if (proc != null && addr > 8)
            {
                byte[] b = new byte[8]; // bytes at [addr-8 .. addr)
                if (proc.ReadMemory(addr - 8, b) == 8) ok = BytesPrecedingAreCall(b);
            }
            _retAddrCache[addr] = ok;
            return ok;
        }

        // True if the 8 bytes ending exactly at a return address contain the CALL
        // that pushed it: a `call rel32` (E8, opcode at addr-5) or a `call r/m`
        // (FF with ModR/M reg field /2) ending at addr. Used to tell a genuine
        // return-address frame from a stray code-looking data word on the stack.
        private static bool BytesPrecedingAreCall(ReadOnlySpan<byte> b8)
        {
            if (b8.Length < 8) return false;
            if (b8[3] == 0xE8) return true;                 // call rel32 (opcode at addr-5)
            for (int p = 0; p <= 6; p++)                    // call r/m (FF /2) ending at addr
                if (b8[p] == 0xFF && ((b8[p + 1] >> 3) & 7) == 2) return true;
            return false;
        }

        private string WinDir()
        {
            if (_winDir == null)
            {
                try { _winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows); }
                catch { _winDir = ""; }
            }
            return _winDir ?? "";
        }

        private bool SameModule(ulong a, ulong b)
        {
            if (_moduleMap == null) return true;
            var ma = _moduleMap.Resolve(a);
            var mb = _moduleMap.Resolve(b);
            return ma != null && mb != null && ma.BaseAddress == mb.BaseAddress;
        }

        // Sorted lookup of the program's own discovered functions (app code only),
        // so a return address can be floored to its enclosing function. System-DLL
        // entries are excluded: a caller label should point at the program.
        private void RebuildCallerIndex()
        {
            var byAddr = new Dictionary<ulong, string>();
            void Add(IEnumerable<TracedFunction>? fns)
            {
                if (fns == null) return;
                foreach (var f in fns)
                {
                    if (!IsAppCode(f.Address)) continue;
                    if (!byAddr.TryGetValue(f.Address, out var existing) || string.IsNullOrEmpty(existing))
                        byAddr[f.Address] = f.DisplayName;
                }
            }
            Add(_session?.Dataset.Functions);
            Add(_liveDataset?.Functions);

            var addrs = new ulong[byAddr.Count];
            byAddr.Keys.CopyTo(addrs, 0);
            Array.Sort(addrs);
            var names = new string[addrs.Length];
            for (int i = 0; i < addrs.Length; i++) names[i] = byAddr[addrs[i]];
            _idxAddr = addrs;
            _idxName = names;
        }

        // Build and render the recursive caller tree (B) for the selected function:
        // its direct callers, then their callers, …, from the global reverse-edge
        // map. Bounded by depth and a total-node budget; a function already on the
        // current path is shown as recursion and not re-expanded.
        private void RefreshCallersView()
        {
            var roots = new List<CallersView.CallerNode>();
            int budget = MaxCallerNodes;
            var path = new HashSet<ulong> { _callersFor };

            if (_callerEdges.TryGetValue(_callersFor, out var direct) && direct.Count > 0)
            {
                foreach (var kv in OrderByCountDesc(direct))
                {
                    if (budget <= 0) break;
                    budget--;
                    roots.Add(BuildCallerNode(kv.Key, kv.Value, 0, path, ref budget));
                }
            }

            long observed = _calleeTotals.TryGetValue(_callersFor, out var ct)
                ? ct
                : (_callerEdges.TryGetValue(_callersFor, out var d2) ? SumValues(d2) : 0);
            string title = _fnNames.TryGetValue(_callersFor, out var nm) ? nm : CallerTitleFor(_callersFor);
            Callers.Show(title, observed, roots);
        }

        private CallersView.CallerNode BuildCallerNode(ulong caller, long count, int depth, HashSet<ulong> path, ref int budget)
        {
            bool cycle = path.Contains(caller);
            var node = new CallersView.CallerNode
            {
                Address = caller,
                Caller = _fnNames.TryGetValue(caller, out var n) ? n : DescribeAddr(caller),
                Module = _moduleMap?.Resolve(caller)?.Name ?? "",
                Count = count,
                IsRecursion = cycle,
            };

            if (!cycle && depth + 1 < MaxCallerDepth && budget > 0
                && _callerEdges.TryGetValue(caller, out var sub) && sub.Count > 0)
            {
                path.Add(caller);
                foreach (var kv in OrderByCountDesc(sub))
                {
                    if (budget <= 0) break;
                    budget--;
                    node.Children.Add(BuildCallerNode(kv.Key, kv.Value, depth + 1, path, ref budget));
                }
                path.Remove(caller);
            }
            return node;
        }

        private static List<KeyValuePair<ulong, long>> OrderByCountDesc(Dictionary<ulong, long> d)
        {
            var list = new List<KeyValuePair<ulong, long>>(d);
            list.Sort((a, b) => b.Value.CompareTo(a.Value));
            return list;
        }

        private static long SumValues(Dictionary<ulong, long> d)
        {
            long s = 0;
            foreach (var v in d.Values) s += v;
            return s;
        }

        // Live-update just the header counts for the selected function (cheap; no
        // tree rebuild) as new calls fold in during capture.
        private void UpdateCallersHeader()
        {
            long observed = _calleeTotals.TryGetValue(_callersFor, out var ct)
                ? ct
                : (_callerEdges.TryGetValue(_callersFor, out var d2) ? SumValues(d2) : 0);
            int direct = _callerEdges.TryGetValue(_callersFor, out var d) ? d.Count : 0;
            string title = _fnNames.TryGetValue(_callersFor, out var nm) ? nm : CallerTitleFor(_callersFor);
            Callers.UpdateHeader(title, observed, direct);
        }

        private string CallerTitleFor(ulong destination)
        {
            if (_liveDataset != null)
                foreach (var f in _liveDataset.Functions)
                    if (f.Address == destination) return f.DisplayName;
            return DescribeAddr(destination);
        }

        // A caller row was clicked: navigate to it (select in the list if present,
        // move the hex view, recentre the graph) WITHOUT disturbing the running
        // capture — the caller is app code, not one of the hooked entries.
        private void OnCallerSelected(ulong address)
        {
            bool inList = FunctionList.SelectByAddress(address);
            GraphView.SetSelected(address);
            if (_currentPe != null && _currentPe.TryVaToFileOffset(address, out uint off)) Hex.GoTo(off);
            else Hex.GoTo(address);
            StatusText.Text = inList
                ? $"Caller {DescribeAddr(address)} — selected."
                : $"Caller {DescribeAddr(address)} — shown in the Memory tab.";
        }

        // Start capturing the first of <candidates> that can be safely hooked
        // (one function only). Shared by manual select and auto-capture-at-launch.
        private void StartCaptureOn(List<ulong> candidates, string label, int maxFunctions = 1, int bufferRecords = 2048, bool preserveLog = false)
        {
            if (_session == null || candidates.Count == 0) return;

            // The target can exit between launch and a click-to-refocus; instrumenting
            // a gone process fails deep in the engine (VirtualAllocEx -> access
            // denied). Catch it here and say so plainly.
            if (!_session.Process.IsAlive)
            {
                Diag($"couldn't start capture on {label} — target process has exited.");
                if (StatusText != null) StatusText.Text = "Target process has exited.";
                return;
            }

            _apiCaptureMode = false; // a focused/normal start; OnCaptureApi re-sets this when broad
            _maxCursorSeen = 0;
            try
            {
                _capture = CaptureSession.Start(_session.Process.Pid, candidates,
                    maxFunctions: maxFunctions, bufferRecords: bufferRecords,
                    out int instrumented, out int skipped, out string? firstError);
                CallList.Configure(_moduleMap);
                // A refocus / single-function start within the same session keeps the
                // accumulated call log (and the arguments it backs); only loading a
                // fresh target wipes it.
                if (!preserveLog)
                {
                    _captured.Clear();
                    CallList.Clear();
                    ClearCallerGraph();
                    _autoUnhooked.Clear();
                }
                _diag.Add($"capture.Start({candidates.Count} candidate(s)): instrumented={instrumented} skipped={skipped} firstError={firstError ?? "(none)"}");

                if (instrumented == 0)
                {
                    _capture?.Dispose();
                    _capture = null;
                    string why = firstError ?? "no candidate could be safely hooked.";
                    Diag($"couldn't start capture on {label} — {why}");
                    return;
                }

                _pollTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
                _pollTimer.Tick += OnPollTick;
                _pollTimer.Start();
                _captureFocus = candidates.Count == 1 ? candidates[0] : 0;

                Diag($"capturing {label} · {instrumented} hook(s) installed · 0 calls yet");
            }
            catch (Exception ex)
            {
                string why = _session.Process.IsAlive ? ex.Message : "target process has exited.";
                Diag("start capture failed: " + why);
                _capture?.Dispose();
                _capture = null;
            }
        }

        // "Capture only" condition: drop polled records that don't satisfy it
        // before they're logged / folded / counted. Every call is still recorded
        // in-target; this just narrows what the host keeps (the analysis form of a
        // data-driven hook). Applies live — changing it affects subsequent polls.
        private void ApplyCaptureCondition(List<CallRecord> recs)
        {
            var cond = _captureCondition;
            if (cond == null || recs.Count == 0) return;
            recs.RemoveAll(r => !cond.Matches(r, ResolveCalleeName));
        }

        private void OnCaptureConditionChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            string text = CaptureCondBox.Text ?? "";
            if (string.IsNullOrWhiteSpace(text)) { _captureCondition = null; return; }

            var cond = CaptureCondition.Parse(text, out string? error);
            if (error != null)
            {
                _captureCondition = null; // malformed -> capture everything, with a visible note
                if (StatusText != null) StatusText.Text = "Capture only — " + error;
                return;
            }
            _captureCondition = cond;
            if (_capture != null && StatusText != null)
                StatusText.Text = $"Capture only: {cond!.Source} — applies to new calls.";
        }

        private async void OnPollTick(object? sender, EventArgs e)
        {
            var cap = _capture;
            if (cap == null || _polling) return; // skip if a previous poll is still draining

            UpdateClearCallsState(); // a live poll loop is running — Clear calls is available

            // Stop cleanly if the target has exited. A dead target makes Poll() drain
            // nothing without error, which would otherwise leave the trace stuck on
            // "running" and let a later click-to-refocus try to allocate in a gone
            // process (VirtualAllocEx -> access denied).
            // Finish the attempt when the target exits, OR when the watch caught a fatal
            // fault but the target is held alive at the WER dialog (so we don't wait
            // forever / misread a crashed bisection test as clean). Gated on
            // _startupActive so stale per-attempt flags never colour an unrelated capture.
            bool startupTrace = _startupActive;
            bool faulted = startupTrace && _faultSeenThisAttempt;
            bool stalledCrash = faulted && cap.IsTargetAlive; // crashed but WER-held
            if (!cap.IsTargetAlive || stalledCrash)
            {
                // A 0xCxxxxxxx exit code is an NTSTATUS crash (named). The crash watch,
                // when attached, already logged the live fault and (when pinnable) wrote
                // the culprit's RVA. (A WER-stalled crash has no exit code yet.)
                string detail = cap.TryGetTargetExitCode(out uint ec)
                    ? $" (exit code 0x{ec:X8}{DebugExceptionInfo.ExitCodeNote(ec)})"
                    : "";
                bool appended = _crashAppendedThisAttempt;
                var armedPool = startupTrace ? new List<ulong>(cap.HookedTargets) : null;
                bool search = startupTrace && AutoBisectCrashes?.IsChecked == true && !_startupStop && _startupPath != null;
                int pid = cap.Pid;

                StopCapture();
                if (stalledCrash) { try { TargetProcess.Kill(pid); } catch { } } // unstick the WER-held crash

                // (A) A bisection TEST run just ended: crashed if a fatal fault was seen,
                //     else it exited without faulting = the subset is clean.
                if (_bisecting)
                {
                    if (search) { BisectStep(crashed: faulted); return; }
                    _bisecting = false; _bisectArmOnly = null;
                    Diag("auto-bisection stopped.");
                    if (StatusText != null) StatusText.Text = "Auto-bisection stopped.";
                    return;
                }

                // (B) Unattributable crash + opt-in: binary-search (hidden) to isolate it.
                //     (A pinnable crash was already written to the skip-list by the watch.)
                if (search && faulted && !appended && armedPool != null && armedPool.Count > 1
                    && _bisectRelaunches < MaxBisectRelaunches)
                {
                    BeginBisection(armedPool);
                    return;
                }

                // (C) Terminal — report and stop (the crash/culprit was already logged).
                Diag("target process has exited" + detail + " — capture stopped.");
                if (StatusText != null) StatusText.Text = "Target process has exited — capture stopped.";
                return;
            }

            // Auto-bisection survive check: a hidden test subset still running this long
            // with no fatal fault is clean (the culprit isn't in it). Discard the hidden
            // instance and advance the search.
            if (_bisecting && _bisectDeadline != 0 && Environment.TickCount64 >= _bisectDeadline
                && AutoBisectCrashes?.IsChecked == true)
            {
                _bisectDeadline = 0;
                int pid = cap.Pid;
                StopCapture();
                TargetProcess.Kill(pid);
                BisectStep(crashed: false);
                return;
            }

            // Diagnostic: did the in-target stub write anything? If this stays 0,
            // the hooked function simply isn't being called (or the patch didn't
            // take); if it grows but no calls decode, the drain/decode is at fault.
            try
            {
                int c = cap.PeekWriteCursor();
                if (c > _maxCursorSeen)
                {
                    if (_maxCursorSeen == 0 && c > 0)
                        _diag.Add($"poll: target began writing (cursor={c} bytes) — stub is firing");
                    _maxCursorSeen = c;
                }
            }
            catch { /* ignore peek errors */ }

            // Build/refresh the worker-side caller-chain resolver (UI thread; cheap —
            // it just snapshots the read handle, module map, and function index).
            EnsureChainResolver();
            var resolver = _chainResolver;

            // The whole heavy part of a poll now runs on a worker thread: the record
            // decode + dereference enrichment AND each record's caller-chain
            // extraction (stack unwinding + return-address / UNWIND_INFO probes).
            // Everything it reads is read-only or concurrently safe — the capture's
            // own handle for the ring, ReadProcessMemory + the immutable module map
            // for the chains — and the _polling guard keeps the poll and the
            // resolver's caches touched by one thread at a time. The UI thread is
            // left with only cheap dictionary folds and the WPF row adds.
            // Snapshot the clear generation BEFORE going off the UI thread: if a
            // "Clear calls" runs while this poll is decoding, the batch we drained
            // belongs to the pre-clear trace and must be dropped (see below).
            int clearGen = _captureClearGen;
            _polling = true;
            PolledBatch batch;
            try
            {
                batch = await Task.Run(() =>
                {
                    var polled = cap.Poll();
                    return new PolledBatch { Records = polled, Chains = resolver?.ResolveAll(polled) };
                });
            }
            catch (Exception ex)
            {
                _polling = false;
                if (ReferenceEquals(_capture, cap)) { StatusText.Text = "Capture poll error: " + ex.Message; StopCapture(); }
                else { try { cap.Dispose(); } catch { } } // stopped mid-poll: dispose the orphan
                return;
            }
            _polling = false;

            // Capture was stopped or refocused while we were off the UI thread:
            // discard this batch and dispose the session that StopCapture /
            // StopCaptureQuietly handed off to us (they couldn't close its handle
            // while Poll was still reading through it).
            if (!ReferenceEquals(_capture, cap)) { try { cap.Dispose(); } catch { } return; }

            // "Clear calls" ran while this batch was decoding off the UI thread. The
            // records were drained from the ring before the clear, so showing them now
            // would resurrect the very calls the user just cleared. Drop the batch —
            // Poll() already advanced the ring read cursor, so the same capture keeps
            // recording from where it is; only this stale batch is discarded.
            if (clearGen != _captureClearGen) return;

            var recs = batch.Records;
            var chains = batch.Chains;

            // "Capture only": drop non-matching records, keeping each surviving
            // record aligned with its precomputed chain.
            var cond = _captureCondition;
            if (cond != null && recs.Count > 0)
            {
                var keptRecs = new List<CallRecord>(recs.Count);
                var keptChains = chains != null ? new List<List<(ulong Addr, string Name)>>(recs.Count) : null;
                for (int i = 0; i < recs.Count; i++)
                {
                    if (!cond.Matches(recs[i], ResolveCalleeName)) continue;
                    keptRecs.Add(recs[i]);
                    keptChains?.Add(chains![i]);
                }
                recs = keptRecs;
                chains = keptChains;
            }

            if (recs.Count == 0)
            {
                if (_captureBursting) { _captureBursting = false; System.Windows.Input.Mouse.OverrideCursor = null; }
                if (_captured.Count == 0)
                    StatusText.Text =
                        $"Capturing · {cap.HookedCount} hook(s) · 0 calls yet · target wrote {_maxCursorSeen} bytes " +
                        (_maxCursorSeen == 0
                            ? "(hooked function not called yet — exercise the program, or click a function you know runs)"
                            : "(stub firing; decoding…)");
                return;
            }
            // Heavy startup flood vs caught up: a wait cursor + "catching up" status
            // while batches are large (the post-open window is briefly busy here),
            // cleared to a "ready" status when they subside.
            if (recs.Count >= CaptureBurstBatch && !_captureBursting)
            {
                _captureBursting = true;
                System.Windows.Input.Mouse.OverrideCursor = System.Windows.Input.Cursors.Wait;
            }
            else if (recs.Count < CaptureBurstBatch && _captureBursting)
            {
                _captureBursting = false;
                System.Windows.Input.Mouse.OverrideCursor = null;
            }

            if (_captured.Count == 0) _diag.Add($"poll: first {recs.Count} record(s) decoded");
            _captured.AddRange(recs);
            CallList.AddRecords(recs);
            FunctionList.AddCounts(recs);
            // Caller graph: chains were resolved on the worker thread, so this is now
            // just dictionary updates. Fall back to UI-side resolution only when no
            // resolver was available (e.g. the live session isn't attached yet).
            if (chains != null) FoldCallersPrecomputed(recs, chains);
            else FoldCallers(recs);

            // No host-side decode can keep up with a function called ~a million times
            // a second; such a runaway laps the ring and starves everything else.
            // Drop just that hook so the rest of the trace records cleanly.
            CheckRunaway(recs, cap);

            // Drive the graph timeline from the live list BY REFERENCE: point the
            // model at _captured once, then only refresh the active (tail) window.
            // The old path rebuilt a sorted copy of the ENTIRE capture every poll —
            // O(n log n) on a list growing into the hundreds of thousands during a
            // startup burst, which pegged the UI thread for several seconds.
            if (!ReferenceEquals(_model.Records, _captured)) _model.UseLiveRecords(_captured);
            if (_captured.Count > 0)
            {
                int from = Math.Max(0, _captured.Count - 200);
                _model.SetActiveWindow(_captured[from].Time, _captured[_captured.Count - 1].Time + 1e-9);
                GraphView.RefreshActive();
            }
            string lost = cap.RecordsLost > 0
                ? $" · {cap.RecordsLost} dropped (target outran the poll)"
                : "";
            string runaway = _autoUnhooked.Count > 0
                ? $" · {_autoUnhooked.Count} runaway hook(s) auto-removed"
                : "";
            StatusText.Text = _captureBursting
                ? $"Capturing startup… catching up · {_captured.Count} calls (window briefly busy){lost}{runaway}"
                : $"✓ Capturing · {cap.HookedCount} hook(s) · {_captured.Count} calls{lost}{runaway}";
        }

        private void OnStopCapture(object sender, RoutedEventArgs e)
        {
            // The user explicitly stopped: latch it so any pending relaunch (or one
            // already in flight) bails instead of popping up / resuming another target,
            // and end any auto-bisection search.
            _startupStop = true;
            _bisecting = false;
            _bisectArmOnly = null;
            _bisectDeadline = 0;
            StopCapture();
        }
        private void StopCapture()
        {
            _startupActive = false;
            if (_debugWatch != null) { _debugWatch.Stop(); _debugWatch = null; }
            StopDllCapture();
            StopChildFollow();
            StopHwbp();
            _captureFocus = 0;
            _apiCaptureMode = false;
            if (_captureBursting) { _captureBursting = false; System.Windows.Input.Mouse.OverrideCursor = null; }
            if (_pollTimer != null) { _pollTimer.Stop(); _pollTimer.Tick -= OnPollTick; _pollTimer = null; }
            var cap = _capture;
            _capture = null; // mark inactive immediately so an in-flight poll disposes its own session
            if (cap != null && !_polling)
            {
                // No poll in flight — safe to drain the tail and dispose here.
                try
                {
                    var tail = cap.Poll();
                    ApplyCaptureCondition(tail);
                    _captured.AddRange(tail);
                    CallList.AddRecords(tail);
                    FunctionList.AddCounts(tail);
                    FoldCallers(tail);
                }
                catch { /* ignore final drain errors */ }
                try { cap.Dispose(); } catch { }
            }
            // If a poll IS in flight we leave cap for the poll continuation to
            // dispose (it sees _capture != cap): closing its handle here would pull
            // it out from under an in-progress ReadProcessMemory. The last in-flight
            // batch isn't shown, but everything applied up to the previous poll is
            // kept.

            if (_callersFor != 0) RefreshCallersView(); // final, complete tree

            if (_captured.Count > 0 && _liveDataset != null)
            {
                var ds = new TraceDataset
                {
                    Modules = _liveDataset.Modules,
                    Functions = _liveDataset.Functions,
                    Records = new List<CallRecord>(_captured),
                };
                ds.Records.Sort((a, b) => a.Time.CompareTo(b.Time));
                ds.TimeStart = ds.Records[0].Time;
                ds.TimeEnd = ds.Records[ds.Records.Count - 1].Time;

                _model.Load(ds);
                GraphView.SetModel(_model);
                PlayBar.SetData(ds);
                // Keep the call-graph centred on the last-selected function for
                // review (SetModel cleared the selection).
                if (_selectedFunctionAddr != 0) GraphView.SetSelected(_selectedFunctionAddr);
                StatusText.Text = $"Capture stopped · {ds.Records.Count} calls recorded — scrub the timeline to review.";
            }
            else
            {
                StatusText.Text = "Capture stopped · no calls recorded.";
            }

            UpdateClearCallsState();
        }

        // --- clear captured calls, keep capturing ---------------------------

        // Reset everything the host has accumulated for the current trace — the calls
        // log, per-function counts + first-call order, the caller tree, and the
        // butterfly graph — WITHOUT tearing down the live capture. The hooks stay
        // installed and the poll loop keeps running, so subsequent calls are recorded
        // fresh. This is the "clear previous calls and continue" action: reset the log,
        // then exercise one path in the target and see only what that triggers.
        // Contrast Stop capture, which removes the hooks and freezes the trace.
        private void OnClearCalls(object sender, RoutedEventArgs e)
        {
            // Defensive: the button is greyed out when nothing is running, but a stale
            // click could still arrive — don't wipe a loaded/stopped trace out from
            // under the user.
            if (!IsCaptureRunning())
            {
                StatusText.Text = _offlineTrace
                    ? "Clear calls is for a live capture — this is an offline trace. Open it again to start fresh."
                    : "No live capture running — start a capture, then Clear calls resets the log while it keeps recording.";
                return;
            }

            // Bump the clear generation so a batch already drained from the ring but
            // still decoding off the UI thread is dropped instead of reappearing. (Only
            // the _capture poll loop reads this; the callback-driven captures — hardware
            // bp and child-follow — run on the UI thread, so it's a harmless no-op there.)
            _captureClearGen++;

            // Child-follow drives the views from the SELECTED child's retained records
            // (not _captured alone), so reset that target's records + running count too;
            // the follow engine keeps instrumenting and repopulates as calls arrive.
            if (_childView && _childSelectedPid >= 0 &&
                _childTargets.TryGetValue(_childSelectedPid, out var t))
            {
                t.Records.Clear();
                t.TotalCalls = 0;
                t.Item.Display = ChildLabel(t);
            }

            ClearCapturedCalls();

            string what =
                _capture != null ? $"{_capture.HookedCount} hook(s)" :
                _hwbp != null    ? $"{_hwbp.BreakpointCount} breakpoint(s)" :
                _childView       ? $"pid {_childSelectedPid}" : "live capture";
            Diag($"✓ Cleared captured calls — capturing continues · {what} · 0 calls");
        }

        // "Only new on left" toggled by the user (Click fires on real interaction only —
        // never on the XAML initial value or a programmatic change — so this can't misfire
        // at startup). Apply it to the function list right away: ticked hides functions
        // with no calls (and reveals each live as it's first called); unticked restores
        // the full list. It also still gates what Clear calls does to the left (see
        // ClearCapturedCalls). Works during a live capture and on a loaded/offline trace.
        private void OnFilterLeftOnClearClicked(object sender, RoutedEventArgs e)
        {
            if (FilterLeftOnClear.IsChecked == true) FunctionList.HideZeroHit();
            else FunctionList.ShowAllCounts();
        }

        // Keep the toolbar checkbox in lockstep with the function list's own filter
        // buttons: ticked iff the list is hiding 0-hit functions, else unticked (a
        // plain "Show all" or an "Only N hits" filter is not the "only new" state).
        // Setting IsChecked programmatically raises Checked/Unchecked but NOT Click, so
        // this never loops back into OnFilterLeftOnClearClicked. The event isn't raised
        // on dataset loads / ResetCounts, so launching or clearing won't flip the
        // checkbox out from under the user.
        private void OnFunctionFilterChanged(object? sender, EventArgs e)
        {
            if (FilterLeftOnClear != null) FilterLeftOnClear.IsChecked = FunctionList.IsHidingZeroHit;
        }

        // A live capture of any kind is active — matches the concurrency guard the start
        // handlers use: the _capture poll loop (Start capture / Windows API / IAT /
        // Launch & capture / Capture DLL after load), a DLL-at-load debug loop before
        // the DLL maps, a child-follow tree, or a hardware-breakpoint debugger.
        private bool IsCaptureRunning() =>
            _capture != null || _dllCapture != null || _childFollow != null || _hwbp != null;

        // Enable "Clear calls" only while a live capture is running — there's nothing to
        // clear-and-continue otherwise. Called from every capture start/stop transition;
        // the Stop paths recompute (rather than blindly disable), so it stays enabled if
        // another capture mode is still active (e.g. selecting a child while following).
        private void UpdateClearCallsState()
        {
            if (ClearCallsButton != null) ClearCallsButton.IsEnabled = IsCaptureRunning();
        }

        // Reset the host-side accumulated trace (calls log, function counts, caller
        // tree, and butterfly graph) shared by the clear paths. Leaves the live
        // session / hooks / poll loop untouched.
        private void ClearCapturedCalls()
        {
            _captured.Clear();
            CallList.Clear();
            FunctionList.ResetCounts(); // zeroes counts AND first-call ranks (resets to "show all")
            // Optionally show only the calls captured SINCE the clear on the left, too:
            // hide every function with no post-clear calls, and (live) reveal each one as
            // it is first called. Controlled by the "Only new on left" toggle; "Show all"
            // in the function list restores the rest. (When off, ResetCounts above already
            // left the full list visible with counts zeroed.)
            if (FilterLeftOnClear?.IsChecked == true) FunctionList.HideZeroHit();

            // Caller tree + per-call stack: drop the folded reverse-edge map and the
            // panels. Keep _callersFor so the tree refills for the same function as new
            // calls arrive; show an empty tree now for immediate feedback.
            ClearCallerGraph();
            CallStack.Clear();
            if (_callersFor != 0) { EnsureCallerIndex(); RefreshCallersView(); }
            else Callers.Clear();

            // Butterfly graph: it aggregates from _model.Records, which points at
            // _captured by reference, so re-point at the now-empty list (this also
            // clears the active node/link highlight) and rebuild the centred
            // neighbourhood with zero counts.
            _model.UseLiveRecords(_captured);
            if (_selectedFunctionAddr != 0) GraphView.SetSelected(_selectedFunctionAddr);
            else GraphView.RefreshActive();
        }

        // --- copy results to clipboard --------------------------------------

        private void OnCopyResults(object sender, RoutedEventArgs e)
        {
            string text = BuildResultsText();
            try
            {
                Clipboard.SetText(text);
                StatusText.Text = _captured.Count > 0
                    ? $"Copied {_captured.Count} captured call(s) to the clipboard."
                    : "Copied diagnostic state to the clipboard (no calls captured yet).";
            }
            catch (Exception ex)
            {
                StatusText.Text = "Copy failed: " + ex.Message;
            }
        }

        // --- save / open a trace --------------------------------------------

        // The dataset to persist: the live module(s)/functions plus the calls
        // recorded so far (sorted by time). Null if there's nothing worth saving.
        private TraceDataset? CurrentTraceDataset()
        {
            if (_liveDataset == null) return null;
            if (_captured.Count == 0)
                return _offlineTrace ? _liveDataset : null; // re-saving a loaded trace is fine

            var ds = new TraceDataset
            {
                Modules = new List<ModuleInfo>(_liveDataset.Modules),
                Functions = new List<TracedFunction>(_liveDataset.Functions),
                Records = new List<CallRecord>(_captured),
            };
            ds.Records.Sort((a, b) => a.Time.CompareTo(b.Time));
            ds.TimeStart = ds.Records.Count > 0 ? ds.Records[0].Time : 0;
            ds.TimeEnd = ds.Records.Count > 0 ? ds.Records[ds.Records.Count - 1].Time : 1;
            return ds;
        }

        private void OnSaveTrace(object sender, RoutedEventArgs e)
        {
            var ds = CurrentTraceDataset();
            if (ds == null || ds.Records.Count == 0)
            {
                StatusText.Text = "Nothing to save yet — capture some calls first (a saved trace holds the recorded calls).";
                return;
            }

            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save the captured trace",
                Filter = "CDA trace (*.cdatrace)|*.cdatrace|All files (*.*)|*.*",
                FileName = "capture" + TraceArchive.FileExtension,
            };
            if (dlg.ShowDialog(this) != true) return;

            try
            {
                TraceArchive.Save(dlg.FileName, ds);
                StatusText.Text = $"Saved {ds.Records.Count} call(s) to {Path.GetFileName(dlg.FileName)}.";
            }
            catch (Exception ex)
            {
                StatusText.Text = "Save failed: " + ex.Message;
            }
        }

        private void OnExportCsv(object sender, RoutedEventArgs e)
        {
            var ds = CurrentTraceDataset();
            if (ds == null || ds.Records.Count == 0)
            {
                StatusText.Text = "Nothing to export yet — capture some calls first (the CSV holds the recorded calls).";
                return;
            }

            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export the captured trace as CSV",
                Filter = "CSV (*.csv)|*.csv|All files (*.*)|*.*",
                FileName = "capture" + TraceCsvExport.FileExtension,
            };
            if (dlg.ShowDialog(this) != true) return;

            try
            {
                TraceCsvExport.Export(dlg.FileName, ds);
                StatusText.Text = $"Exported {ds.Records.Count} call(s) to {Path.GetFileName(dlg.FileName)}.";
            }
            catch (Exception ex)
            {
                StatusText.Text = "Export failed: " + ex.Message;
            }
        }

        private void OnOpenTrace(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Open a saved CDA trace",
                Filter = "CDA trace (*.cdatrace)|*.cdatrace|All files (*.*)|*.*",
            };
            if (dlg.ShowDialog(this) != true) return;

            TraceDataset ds;
            try { ds = TraceArchive.Load(dlg.FileName); }
            catch (Exception ex) { StatusText.Text = $"Couldn't open trace: {ex.Message}"; return; }

            ApplyLoadedTrace(ds, dlg.FileName);
        }

        // Make a loaded trace the active (offline-review) dataset, driving every view
        // from it. Shared by Open trace and by Compare trace (when picking trace A from
        // a file). Caller has already loaded <paramref name="ds"/>.
        private void ApplyLoadedTrace(TraceDataset ds, string fileName)
        {
            ExitCompareMode(); // a freshly loaded trace invalidates any open comparison

            // Switching to an offline view: stop anything live and release the target.
            StopCaptureQuietly();
            StopDllCapture();
            StopChildFollow();
            _session?.Dispose();
            _session = null;

            SetCallersTarget(0);
            _currentPe = null;
            _captureFocus = 0;
            _apiCaptureMode = false;
            _offlineTrace = true;
            _childView = false;
            ClearStringsTab(); // a saved trace carries no image to mine strings from
            _is64 = true; // bitness isn't stored; addresses are absolute regardless
            _moduleMap = new ModuleMap(ds.Modules);
            _liveDataset = ds; // the active dataset for the views, names, and caller tree
            _selectedFunctionAddr = 0;

            _captured.Clear();
            _captured.AddRange(ds.Records);
            _maxCursorSeen = 0;

            _model.Load(ds);
            GraphView.SetModel(_model);
            PlayBar.SetData(ds);
            FunctionList.LoadFromDataset(ds);
            FunctionList.StampCallOrder(ds.Records); // so "Call order" works on an offline trace
            DisposeFileMap();
            Hex.SetSource(null); // offline: no live memory to show

            // Rebuild the Calls log and the caller graph from the loaded records.
            CallList.Configure(_moduleMap);
            CallList.Clear();
            CallList.AddRecords(ds.Records);
            ClearCallerGraph();
            EnsureCallerIndex();
            FoldCallers(ds.Records);

            string name = Path.GetFileName(fileName);
            StatusText.Text =
                $"Opened {name} · {ds.Modules.Count} module(s) · {ds.Functions.Count} function(s) · " +
                $"{ds.Records.Count} call(s) over {(ds.TimeEnd - ds.TimeStart):0.000}s — offline review " +
                "(click a function for its callers; deeper caller frames need a live target).";
        }

        // --- compare two traces ---------------------------------------------

        private void OnCompareTrace(object sender, RoutedEventArgs e)
        {
            // Trace A is the current trace if there is one; otherwise let the user open a
            // saved trace as A, so two saved traces can be compared with no live session.
            var a = CurrentTraceDataset();
            string labelA;
            if (a == null || a.Records.Count == 0)
            {
                var dlgA = new Microsoft.Win32.OpenFileDialog
                {
                    Title = "Open the first trace to compare (A)",
                    Filter = "CDA trace (*.cdatrace)|*.cdatrace|All files (*.*)|*.*",
                };
                if (dlgA.ShowDialog(this) != true) return;

                TraceDataset loadedA;
                try { loadedA = TraceArchive.Load(dlgA.FileName); }
                catch (Exception ex) { StatusText.Text = $"Couldn't open trace A: {ex.Message}"; return; }

                ApplyLoadedTrace(loadedA, dlgA.FileName); // make A the active offline trace
                a = CurrentTraceDataset();
                if (a == null || a.Records.Count == 0)
                {
                    StatusText.Text = $"{Path.GetFileName(dlgA.FileName)} has no recorded calls to compare.";
                    return;
                }
                labelA = Path.GetFileName(dlgA.FileName) + $"  ·  {a.Records.Count:N0} calls";
            }
            else
            {
                labelA = (_offlineTrace ? "loaded trace (current)" : "current capture") + $"  ·  {a.Records.Count:N0} calls";
            }

            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Choose the trace to compare against (B)",
                Filter = "CDA trace (*.cdatrace)|*.cdatrace|All files (*.*)|*.*",
            };
            if (dlg.ShowDialog(this) != true) return;

            TraceDataset b;
            try { b = TraceArchive.Load(dlg.FileName); }
            catch (Exception ex) { StatusText.Text = $"Couldn't open trace B: {ex.Message}"; return; }

            TraceComparisonResult result;
            try { result = TraceComparison.Compare(a, b); }
            catch (Exception ex) { StatusText.Text = "Compare failed: " + ex.Message; return; }

            string labelB = Path.GetFileName(dlg.FileName) + $"  ·  {b.Records.Count:N0} calls";

            // Replace any previous comparison before starting a new one.
            ExitCompareMode();

            // Overlay the diff onto the butterfly graph: callers/callees of the selected
            // function get recoloured by how each relationship changed between A and B.
            var gd = new GraphDiff(result);
            _graphDiff = gd;
            GraphView.SetDiffMode(addr => gd.Build(addr));
            if (_selectedFunctionAddr != 0) GraphView.SetSelected(_selectedFunctionAddr);

            var win = new CompareWindow(result, labelA, labelB, NavigateToFunction) { Owner = this };
            _compareWindow = win;
            win.Closed += (_, _) =>
            {
                if (!ReferenceEquals(_compareWindow, win)) return; // a newer comparison already took over
                _compareWindow = null;
                _graphDiff = null;
                GraphView.SetDiffMode(null); // back to the live butterfly
                if (_selectedFunctionAddr != 0) GraphView.SetSelected(_selectedFunctionAddr);
                StatusText.Text = "Exited trace comparison — call graph back to the live view.";
            };
            win.Show();

            StatusText.Text = $"Comparing against {Path.GetFileName(dlg.FileName)} — {result.DifferingCount:N0} of {result.Functions.Count:N0} function(s) and {result.EdgeDifferingCount:N0} edge(s) differ. Select a function to see the diff on the graph.";
        }

        // Tear down any active trace comparison: clear the butterfly diff overlay and
        // close the Compare window. Safe to call when no comparison is active. The
        // window's Closed handler early-returns here (we null the field before Close),
        // so there's no double teardown.
        private void ExitCompareMode()
        {
            if (_graphDiff == null && _compareWindow == null) return;
            _graphDiff = null;
            GraphView.SetDiffMode(null); // back to the live butterfly
            if (_selectedFunctionAddr != 0) GraphView.SetSelected(_selectedFunctionAddr);
            var w = _compareWindow;
            _compareWindow = null;
            w?.Close();
        }

        /// <summary>
        /// Select a function across the main views (function list, graph, hex, caller
        /// tree), as if it had been clicked in the list. Public so the Compare window
        /// can jump to a differing function; no-ops with a status note if the address
        /// isn't in the current trace's function list (e.g. it's only in trace B).
        /// </summary>
        public void NavigateToFunction(ulong address)
        {
            if (!FunctionList.SelectByAddress(address))
            {
                StatusText.Text = $"{DescribeAddr(address)} isn't in the current trace's function list.";
                return;
            }
            OnFunctionSelected(this, address);
            Activate(); // surface the main window so the jump is visible behind the Compare window
        }

        private string DescribeAddr(ulong addr)
        {
            if (_moduleMap != null)
            {
                try { return _moduleMap.Describe(addr); } catch { /* fall through */ }
            }
            return "0x" + addr.ToString("X");
        }

        // Resolve a callee address to its real (exported / Windows API) name, or
        // null for synthetic names. Lazily indexed per active dataset (identity
        // check), mirroring EnsureCallerIndex. Feeds the Calls log labels + Win32
        // signature lookup.
        private string? ResolveCalleeName(ulong addr)
        {
            if (!ReferenceEquals(_nameIndexFor, _liveDataset))
            {
                _calleeNames.Clear();
                if (_liveDataset != null)
                    foreach (var f in _liveDataset.Functions)
                        if (!string.IsNullOrEmpty(f.Name)) _calleeNames[f.Address] = f.Name!;
                _nameIndexFor = _liveDataset;
            }
            return _calleeNames.TryGetValue(addr, out var n) ? n : null;
        }

        // Builds a plain-text report. When calls exist, lists them (resolved
        // addresses, args, decoded string dereferences). When none do, dumps the
        // diagnostic state + what was discovered — useful for pasting into a report
        // or for troubleshooting why nothing recorded.
        private string BuildResultsText()
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("CDA — capture results");
            sb.AppendLine(StatusText.Text);
            sb.AppendLine($"host={(Environment.Is64BitProcess ? "x64" : "x86")}");
            sb.AppendLine(_capture != null
                ? $"hooks={_capture.HookedCount}  callsRecorded={_captured.Count}  targetBytesWritten={_maxCursorSeen}"
                : $"callsRecorded={_captured.Count}");
            sb.AppendLine();

            if (_captured.Count > 0)
            {
                int show = 1000;
                int start = Math.Max(0, _captured.Count - show);
                if (start > 0) sb.AppendLine($"(showing last {show} of {_captured.Count} calls)");
                sb.AppendLine($"  {"time(s)",10}  {"caller",-30}    {"callee",-30} arguments / strings");

                for (int i = start; i < _captured.Count; i++)
                {
                    var r = _captured[i];
                    sb.Append($"  {r.Time,10:0.000000}  {DescribeAddr(r.Source),-30} -> {DescribeAddr(r.Destination),-30}");

                    if (r.IntegerArgs != null && r.IntegerArgs.Length > 0)
                    {
                        sb.Append("  args=[");
                        for (int a = 0; a < r.IntegerArgs.Length; a++)
                        {
                            if (a > 0) sb.Append(", ");
                            sb.Append("0x").Append(r.IntegerArgs[a].ToString("X"));
                        }
                        sb.Append(']');
                    }

                    if (r.Dereferences != null && r.Dereferences.Length > 0)
                    {
                        foreach (var d in r.Dereferences)
                        {
                            string? s = d.AsString();
                            if (s != null) sb.Append($"  arg{d.ArgumentIndex}=\"{s}\"");
                        }
                    }
                    sb.AppendLine();
                }
            }
            else if (_liveDataset != null)
            {
                sb.AppendLine($"No calls captured yet. Discovered {_liveDataset.Functions.Count} functions " +
                              $"in {_liveDataset.Modules.Count} module(s):");
                foreach (var m in _liveDataset.Modules)
                    sb.AppendLine($"  module {m.Name}  base=0x{m.BaseAddress:X}  size=0x{m.Size:X}");

                var freq = new Dictionary<ulong, int>();
                foreach (var rec in _liveDataset.Records)
                    freq[rec.Destination] = freq.TryGetValue(rec.Destination, out int c) ? c + 1 : 1;
                var ordered = new List<TracedFunction>(_liveDataset.Functions);
                ordered.Sort((a, b) =>
                {
                    int fb = freq.TryGetValue(b.Address, out int y) ? y : 0;
                    int fa = freq.TryGetValue(a.Address, out int x) ? x : 0;
                    return fb.CompareTo(fa);
                });
                int n = Math.Min(25, ordered.Count);
                sb.AppendLine($"top {n} functions by inbound call sites:");
                for (int i = 0; i < n; i++)
                {
                    var f = ordered[i];
                    int fc = freq.TryGetValue(f.Address, out int v) ? v : 0;
                    sb.AppendLine($"  {DescribeAddr(f.Address),-30} {"\"" + f.DisplayName + "\"",-24} sites={fc}");
                }
            }
            else
            {
                sb.AppendLine("No live session and no captured calls.");
            }

            if (_diag.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("# diagnostic log (most recent run)");
                foreach (var line in _diag) sb.AppendLine("  " + line);
            }

            return sb.ToString();
        }

        // --- playback wiring -------------------------------------------------

        private void OnWindowChanged(object? sender, WindowChangedEventArgs e)
        {
            _model.SetActiveWindow(e.Start, e.End);
            GraphView.RefreshActive();

            // Give the timeline cursor a job: jump the call log (and, via its
            // selection, the hex view) to the call nearest the cursor, and show
            // that call in the status bar. Only act on a genuine user cursor move
            // (scrub or arrow keys) — never on the programmatic SetData fired at
            // capture start/stop — so it works whether or not a capture is running
            // and never overrides a selection made by clicking a function.
            if (!e.ByUser) return;

            double mid = (e.Start + e.End) * 0.5;
            CallRecord? rec = CallList.SelectNearestTime(mid);
            if (rec == null)
            {
                var recs = _model.Records;
                if (recs != null && recs.Count > 0) rec = NearestByTime(recs, mid);
            }
            // Don't clobber the live "Capturing…" line; the selection/hex still move.
            if (rec != null && _capture == null)
                StatusText.Text = $"t={rec.Time:0.000000}s  ·  {DescribeAddr(rec.Source)} → {DescribeAddr(rec.Destination)}";
        }

        // Nearest record to a time in a time-sorted list (binary search).
        private static CallRecord NearestByTime(IReadOnlyList<CallRecord> recs, double t)
        {
            int lo = 0, hi = recs.Count - 1;
            while (lo < hi)
            {
                int mid = (lo + hi) >> 1;
                if (recs[mid].Time < t) lo = mid + 1; else hi = mid;
            }
            int best = lo;
            if (lo > 0 && Math.Abs(recs[lo - 1].Time - t) <= Math.Abs(recs[lo].Time - t)) best = lo - 1;
            return recs[best];
        }

        // --- DPI -------------------------------------------------------------

        protected override void OnDpiChanged(DpiScale oldDpi, DpiScale newDpi)
        {
            base.OnDpiChanged(oldDpi, newDpi);
            UpdateDpiText();
        }

        private void UpdateDpiText()
        {
            var dpi = VisualTreeHelper.GetDpi(this);
            DpiText.Text = $"DPI {dpi.PixelsPerInchX:0}×{dpi.PixelsPerInchY:0}  ·  scale {dpi.DpiScaleX * 100:0}%";
        }

        protected override void OnClosed(EventArgs e)
        {
            _dllCapture?.Stop();
            _childFollow?.Stop();
            _hwbp?.Stop();
            _hwbp?.WaitForExit(600); // let it clear debug registers + detach before we exit
            if (_pollTimer != null) { _pollTimer.Stop(); _pollTimer = null; }
            if (!_polling) _capture?.Dispose(); // don't close the handle under an in-flight poll at shutdown
            _session?.Dispose();
            DisposeFileMap();

            // Best-effort sweep of the fixed-base (ASLR-stripped) copies written this
            // session. A copy whose target is still running (we detach and leave it
            // alive) stays locked and is left for a later launch to sweep.
            foreach (var original in _fixedBaseOriginals)
                FixedBaseImage.CleanupNear(original);

            base.OnClosed(e);
        }
    }
}
