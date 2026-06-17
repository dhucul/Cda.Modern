# CDA — Modern

A ground-up rewrite of the original **CDA / Function_Debugger** — a Windows
dynamic-analysis tool that discovers a program's functions, instruments their
entries with inline hooks, and records and visualizes the calls (with arguments)
as the program runs. It works on **both 32-bit and 64-bit** targets and is
crisp on 4K/5K displays.

This is a real instrumentation tool of the Detours / MinHook class: it writes a
small jump at a function's entry to a generated capture stub, records the call,
and chains back through a relocated trampoline. Use it on software you own or are
authorized to analyze.

---

## Status

Working and validated on real targets. Implemented and confirmed:

- **Static module view** — open any PE (EXE/DLL/SYS), parse headers, list exports
  and statically-discovered functions, browse the raw bytes in the hex view.
- **Cross-process live capture** — attach, hook selected functions, and stream
  calls with decoded integer arguments and string dereferences.
- **Suspended-launch startup trace** — launch an EXE frozen, hook before its first
  instruction runs, then release it to capture startup flow (with a packer guard
  and a post-start fallback).
- **DLL-at-load (DllMain) capture** — launch a host, and hook a target DLL the
  moment it loads, before `DllMain` runs.
- **Disable ASLR (reproducible bases)** — optionally launch a target (startup
  trace, DLL-at-load, or child-follow) with ASLR off, so its image maps at the
  same base every run and the captured absolute addresses line up across runs and
  across saved traces. CDA launches a throwaway copy of the image with its
  `/DYNAMICBASE` opt-in stripped (the reliable per-image fix), plus a per-process
  bottom-up mitigation policy. Nothing global is changed; requires Windows
  mandatory ASLR (force-relocate) to be off, which is the default. Only the
  launched image (the root, for child-follow) is pinned — spawned children keep
  their own ASLR.
- **Windows-API capture** — in one click, hook the OS functions a program imports
  (kernel32, user32, ntdll, …) and record every call to them with arguments and
  decoded strings.
- **Caller tracing** — every captured call also snapshots the stack, so a call
  routed through CRT/runtime wrappers is traced back to the function in *your*
  program that triggered it: a per-call **Call stack** and a recursive **Called
  by** caller tree. On x64 this is sharpened by exact `.pdata` stack unwinding.
- **Follow children** — launch a program under a debug loop and instrument every
  process it spawns, each from its own first instruction; switch between them in a
  target picker (with an optional skip of OS/system children).
- **Runaway protection** — a broad trace holds back tiny/high-fan-in leaf
  primitives up front, and adaptively un-hooks any function that still floods the
  ring at runtime, so one hot utility can't drown out the rest of the trace.
- **Strings + cross-references** — mine every printable string (ASCII and UTF-16)
  out of the launched/opened image and, for each, resolve the functions whose code
  loads its address. Search the list, then click a string to jump straight to the
  function that uses it — the Strings-window-with-xrefs of IDA/Ghidra, wired into
  the same click-to-focus navigation as the function list and graph.
- **Conditional capture, save/load, symbols** — a "Capture only" host-side filter,
  saving/opening traces as `.cdatrace` for offline review, PDB symbol names where
  available, and search / filter / bookmarks in the call log. The function list
  also has a **call-count filter** (hide never-called functions, or isolate those
  hit exactly _N_ times) for pruning a busy list after a capture.
- **Self-tests** for the inline-hook codegen and the capture stub + ring buffer
  pass for the current build's architecture.

The build compiles and runs in Visual Studio 2022 on .NET 8.

---

## Why the rewrite

The legacy app was pinned to a dead stack: **.NET Framework 3.5**, **C# 2**,
**x86 only**, **WinForms** plus the third-party `Be.Windows.Forms.HexBox`, and —
fatally — **Managed DirectX 1.1** (`Microsoft.DirectX.Direct3D`), discontinued
~2006 and unloadable on modern .NET. It also had no DPI awareness, so it rendered
blurry on high-resolution monitors.

The DirectX use was never 3D: it created a Direct3D 9 device on a WinForms panel
and drew the call graph as a point list (nodes), a line list (edges), and module
labels — a 2D rasterizer. That maps cleanly onto WPF's resolution-independent
vector drawing, which is what this rewrite uses. (WPF still composites through
Direct3D inside the OS; the requirement was to retire the dead *Managed DirectX*
dependency, not to avoid the GPU.)

## Stack

- **.NET 8**, **WPF**, built for **x64 and x86**
- **Per-Monitor v2 DPI** awareness (`Cda.App/app.manifest`) — re-renders crisply
  across monitors of different scale factors; the status bar shows the live DPI
- **Iced** (`Iced` NuGet) for x86/x64 instruction decoding, call-site discovery,
  and trampoline (block) encoding
- `requireAdministrator` in the manifest — instrumenting another process needs
  debug privilege, so run Visual Studio (and the app) **elevated**

---

## Architecture

Two assemblies, with a strict one-way dependency (`Cda.App` → `Cda.Core`, never
the reverse):

- **`Cda.Core`** — the engine. No WPF, no UI. PE parsing, the process/memory
  model, the CPU abstraction, the disassembler integration, inline-hook codegen,
  the capture stubs + lock-free ring buffer, and the capture/launch/debug-load
  sessions.
- **`Cda.App`** — the WPF UI. Views, the call-graph and timeline visualizations,
  the theme, and `MainWindow`, which orchestrates the engine.

Argument values are dereferenced **host-side**: the in-target stub records raw
register/stack values into the ring buffer with minimal work, and the host reads
pointed-to memory (e.g. strings) afterward with `ReadProcessMemory`. This keeps
the injected code tiny and safe.

Each record also carries a short **stack snapshot** — a fixed number of words from
the entry stack pointer. The host walks it afterward (skipping system/runtime
frames and validating return addresses against the target's code, and on x64 using
exact `.pdata` unwinding) to attribute a call back to the program's own function.
This powers the **Call stack** (one call's chain) and **Called by** (a caller tree
composed across calls) views. As with arguments, the stub only copies raw words;
all interpretation is host-side.

The poll that drains the ring runs its heavy work — decode, dereference enrichment,
and caller-chain extraction — on a worker thread, so a heavy startup flood doesn't
freeze the window; the UI thread is left with cheap dictionary folds and row adds.

### Bitness rule

The **x64 build is the universal host**: it can instrument x64 targets and
WOW64 (32-bit) targets. The only unsupported direction is an x86 host trying to
instrument a 64-bit target, which is guarded against with a clear message. In
practice, build and run the **x64** configuration.

---

## What it does

**Open module (static).** Parse a PE and list its exports and the functions found
by a static call-site scan (Iced). The hex view is backed by a **memory-mapped
file**, so a module of any size is browsable with almost no managed-heap cost —
only the bytes you scroll to are paged in. Very large files skip the full read +
static scan (which can't fit in a 32-bit address space) and open straight into
the mapped hex view; discover their functions dynamically by launching/attaching.

**Attach to process.** Read-only discovery against a running process: enumerate
modules, scan for functions and call sites, and populate the views (no hooks
installed until you capture).

**Live capture.** Instrument one or more discovered functions with inline entry
hooks and stream their calls — caller → callee, integer arguments, and any
decoded string arguments — into the Calls log, the per-function call counts, the
graph, and the timeline.

**Launch & capture (startup trace).** Create the target suspended, discover and
arm a broad set of its functions while it is still frozen, then resume it so the
startup call flow is captured from the first instruction. Packed executables
(only an unpacker stub visible up front) are detected and traced after startup
instead, so hooking can't corrupt the unpacker. The traced target runs under a
side **debugger** (`Engine/DebugCrashWatch`): if a spliced hook crashes it, the
fault is caught **live** (faulting `module+0xRVA`, access, instruction bytes,
registers) and pinned, where possible, to the hook that caused it — instead of the
target dying with only an opaque exit code. The fault is reported and the capture
stops. To trace past an offending hook, add its RVA to **`cda_hook_skip.txt`** (a
static skip-list next to the exe — one hex RVA per line; read fresh each launch)
and re-launch: every other function is hooked, that one isn't. Use the
`CDA_HOOK_RANGE` slice (hook only candidates _skip..skip+take_, dropped in
`cda_hook_range.txt`) to bisect down to the offending RVA in the first place.

**Capture DLL (from load).** Launch a host (default `rundll32` of the matching
bitness, or your own host EXE) under a Win32 debug loop and hook the target DLL
the instant it maps — before `DllMain` runs.

**Follow children.** Launch a program under a `DEBUG_PROCESS` loop and instrument
every process it spawns, each frozen at creation so it's traced from its own first
instruction. Each instrumented process is a selectable target with its own dataset
and call log; the rest keep recording in the background while you inspect one.
An optional toggle skips OS/system children so an app tree isn't buried under
service processes.

**Capture Windows API.** On an attached process, hook the Windows API entry points
it imports — each resolved from the app modules' import tables to the real
loader-bound address — and record every call with arguments and decoded strings.
Ultra-hot primitives (critical-section / heap / last-error) are skipped to avoid
flooding. The broad trace keeps running as you click around, so selecting an API
inspects its callers without collapsing the trace.

**Called by (caller tree).** For the selected function, a recursive tree of who
calls it — its direct callers, then *their* callers, on back toward the entry
point. It is built from the stack snapshot taken with every call and composed
across all of them, so it reaches further back than any single snapshot; it is
depth- and node-bounded and marks recursion. A call that reaches an API through a
runtime wrapper is attributed to the app function that started it, not the wrapper.

**Call stack (per call).** Click one call in the Calls log to see that single
call's chain back into your program, innermost frame first, reconstructed from its
stack snapshot.

**Capture only (conditional capture).** Type a filter expression to keep only the
calls you care about (e.g. by callee or argument). Every call is still recorded in
the target; the filter is applied host-side as batches arrive, so it narrows the
log live without re-instrumenting.

**Clear calls (reset, keep capturing).** Reset the recorded calls, per-function
counts, caller tree, and graph shown so far **without** removing the hooks — the
capture keeps running, so subsequent calls are recorded fresh. Use it to clear the
noise, then exercise one action in the target and see only what that triggers (any
batch already drained from the ring but mid-decode is dropped, so pre-clear calls
can't reappear). With **Only new on left** ticked (the default, beside the button),
the function list also switches to its live **Hide 0-hit** view, so the left pane
fills in with just the functions hit *since* the clear, as they run; untick it to keep
the full list with counts zeroed. Toggling that checkbox also applies to the list
immediately (tick = hide 0-hit, untick = show all), during a live capture or on a
loaded trace. The button is enabled only while a capture is live; **Stop capture**
instead removes the hooks and freezes the trace for review.

**Strings (cross-references).** After **Open module**, **Launch & capture**, or
**Attach** (the latter two read the live process straight through
`ReadProcessMemory`), the Strings tab lists every printable string found in the
image — ASCII and UTF-16 — across all of its sections (including read-only literals
the compiler parks in `.text`). A string is a NUL-terminated run, the C-string
definition, so disassembled code bytes don't masquerade as text. For a live target
it scans the main image **plus the app's own DLLs** (the modules in the main
executable's own directory — not the OS modules, nor shared runtimes installed
elsewhere), so an app's strings aren't buried under the OS's; the main image carries
full cross-references, the app DLLs are listed for their strings. A static
disassembly pass records, for each string, the
discovered functions whose code loads its address (an x64 `lea reg,[rip+str]`, an
x86 `push offset str` / absolute `mov`), flooring each reference site to its
enclosing function. By default it lists **every** string in the module —
independent of any function or capture, like IDA's Strings window — and you can
type to search or tick **Only referenced** to narrow to just the ones some function
loads by address. Double-click a string — or pick one of its referencing functions
in the **Referenced by** panel below — to jump to that function exactly as a
list/graph click would: it highlights in the function list, re-centres the graph,
navigates the hex view, and (with Auto-capture on) refocuses a running trace onto it.

**Save / open trace.** Write the captured calls (with modules and functions) to a
`.cdatrace` file and reopen it later for offline review — the function list, graph,
call log, caller tree, and timeline all work from a saved trace without a target.

**Export CSV.** Dump the captured calls to a spreadsheet-friendly `.csv` — one row
per call (time, caller, callee, callee module, integer arguments, decoded strings),
with resolved `module+0xRVA` and exported/symbol names — for Excel, pandas, or grep.
It is one-way (use **Save / open trace** for a file CDA can reopen), RFC-4180 quoted,
and UTF-8 with a BOM so decoded strings render correctly.

**Compare traces.** Diff trace **A** against trace **B** to see *where two runs
diverge in what they executed* — which functions ran only in one run, which ran a
different number of times, and which **caller→callee relationships** appeared,
vanished, or changed frequency. Trace A is the current trace (a live capture or an
opened `.cdatrace`); with nothing loaded, **Compare trace…** simply prompts for two
saved `.cdatrace` files, so you can diff two captures with no live session at all. Functions are matched on a
**stable identity** — by `module+0xRVA` first (the exact identity within the same
binary, invariant under ASLR *and* under whether symbols were available for one
capture but not the other), falling back to `module!name` (so the same function in
two different builds, RVA shifted but name stable, still lines up). The **edge** diff
matches each endpoint by `module+0xRVA` alone (name-independent and ASLR-invariant),
so a caller→callee relationship lines up across two runs of the same binary regardless
of which endpoints were named or ever themselves called — it is most meaningful for
runs of the same binary. The Compare
window shows a sortable table (status · calls A · calls B · Δ, colour-coded) beside a
**"where they differ" chart** — a diverging bar graph of the most-divergent functions
(green = ran more in B / new, red = ran fewer / removed). Prune the table by name, by
**Differences only** (hide functions called the exact same number of times), by a
**Min Δ** threshold (hide functions whose count changed by fewer than _N_ calls), or by
a **Min %** threshold (hide functions whose _relative_ change `|Δ| ÷ max(callsA,callsB)`
is under _X_% — a new/removed function counts as 100% and is always kept, while a slight
drift on a hot function reads ~0% and drops out); the thresholds combine, and a
"showing X of Y" readout reports how many remain. Counts come from the recorded calls,
so it works on a live capture and a reopened trace alike.

A **String arguments** tab diffs the decoded string arguments themselves — which file
paths, registry keys, URLs, or format strings a run passed to its calls, and how many
times — matched on the string value, so it surfaces content one run touched and the
other didn't (e.g. a path opened only in B). A **First-call order** tab diffs the order
functions were *first* called in each run, aligning the two first-call sequences by a
**longest-common-subsequence** so a cascade doesn't masquerade as a reorder: a function
that kept its relative position reads `in order` (even if its raw rank shifted because
other functions were added or removed before it), only a genuine reorder reads `moved`,
and `only A` / `only B` mark functions called in just one run — useful for spotting
startup-flow divergence. **Copy report** captures all of it (function/edge,
string-argument, and first-call-order diffs) as text.

While the comparison is open the main **butterfly call graph becomes a diff view**:
selecting a function (in the list, the graph, or by double-clicking a row in the
Compare window) recolours its callers and callees by how each relationship changed —
green for more calls / new, red for fewer / removed, grey for unchanged — each
labelled with its A→B counts. Closing the Compare window restores the live graph.

**Click-to-focus.** Click any function (in the list or the graph) to re-focus a
running single/startup trace onto just that function.

**Copy results.** A column-aligned, paste-ready report of the captured calls
(resolved addresses, arguments, decoded strings) plus a diagnostic log.

**Self-test.** Validates the byte-exact pieces — inline-hook patch sizing /
stolen-byte relocation / jump encoding, and the capture stub + ring buffer — for
the current build's architecture.

---

## The UI

- **Function list (left)** — Order / Address / Module / Function / **Calls**.
  Columns auto-fit and the pane is sized to show everything without dragging; call
  counts update live during capture. Click a row to inspect, focus, and re-center the
  graph on that function. Click any column header to sort by it; the **Order** column
  is each function's **first-call rank** — 1 for the first function called in the
  trace, 2 for the next newly-called one, and so on (blank until a function is hit) —
  so sorting by it (or the **Call order** button) lists the functions **in the order
  they were first called**, with never-called ones at the bottom. It fills in live
  during capture and also works on a loaded `.cdatrace`. Above the list are a
  name/module/address text filter and a **call-count filter** for pruning a busy list
  after a capture: **Hide 0-hit** drops every function that was never called, **Only
  _N_ hits** keeps just the ones called exactly *N* times (type the count and press
  Enter), and **Show all** restores the list. The count filter is non-destructive — it
  hides rows rather than deleting them, composes with the text filter, and leaves live
  counting, the graph, and the dataset untouched — and a "showing X of Y" readout
  reports how many remain. **Hide 0-hit** updates **live** — a function appears the
  moment it's first called — so it pairs with **Clear calls** to watch only the
  functions a specific action exercises. **Only _N_ hits** is a snapshot of the counts
  when applied, so re-click it to re-prune as more calls arrive (the **Call order** sort
  is likewise a snapshot — re-click to re-apply once more functions have been hit).
- **Call graph (center)** — a **caller/callee ("butterfly") view** centered on the
  selected function: who calls it (left) and what it calls (right), each labeled
  and weighted by observed call count. Click a neighbor to walk the call
  structure; it updates live during capture.
- **Calls / Called by / Call stack / Memory tabs (right)**
  - **Calls** — the live call log with arguments and decoded strings, a
    **"Keep last" cap** (blank = unlimited), and a **Follow** toggle for tailing.
  - **Called by** — a recursive caller tree for the selected function; expand a
    caller to see its callers, tracing back toward the entry point.
  - **Call stack** — the local call chain for the call selected in the Calls log,
    innermost frame first.
  - **Memory** — the on-demand hex viewer (file image or live process). Select a
    byte range (click, drag, or shift-click) and copy it as hex or text (Ctrl+C, or
    the right-click menu).
  - **Strings** — every string mined from the image, searchable, with the
    functions that reference each; double-click a string (or pick a referencing
    function) to jump to that code. Selecting a string shows its **full value**
    (any length, wrapping and copyable) in the box below. Populated after Open
    module, Launch & capture, or Attach (read live from the process image) — the
    scan and the (potentially large) list build run **off the UI thread**, so the
    window stays responsive while it fills in.
- **Timeline (bottom)** — a call-density timeline with a scrub cursor. Click or
  drag to scrub; with focus, **← / →** step the cursor precisely (Ctrl = larger,
  Home / End = ends). Scrubbing navigates the Calls log (and the hex view) to the
  call nearest the cursor.
- A professional dark theme throughout, DPI-correct vector rendering, and a status
  bar with a live DPI readout.

---

## Build & run

1. Open `Cda.Modern.sln` in **Visual Studio 2022** (17.8+) with the **.NET 8 SDK**.
2. Select the **x64** configuration (Debug or Release).
3. Run **elevated** (instrumenting another process requires administrator /
   debug privilege). Press **F5**.

On launch a synthetic demo trace loads so the visualization is immediately
exercisable. From there:

- **Open module (PE)…** to inspect a binary statically.
- **Attach to process…** for read-only discovery, then **Start capture** on a
  selected function — or **Capture Windows API** to hook every OS function it
  imports at once.
- **Launch & capture…** to trace an EXE from startup.
- **Capture DLL…** to trace a DLL from the moment it loads.
- **Follow children…** to trace a program and every process it spawns.
- **Open / Save trace…** to review a captured `.cdatrace` offline or keep one.
- **Export CSV…** to dump the captured calls to a spreadsheet (Excel / pandas / grep).
- **Compare trace…** to diff the current trace against a saved one and chart where they differ.
- **Self-test** to verify the codegen/ring on this machine.

---

## Windows API surface

Every native call lives in the engine (`Cda.Core`), centralized in three files —
`Process/NativeMethods.cs` (the bulk), `Process/Privileges.cs` (token privileges),
and `Engine/SymbolResolver.cs` (symbols). The WPF app makes no P/Invoke calls of
its own; it goes through the engine. Process *listing* uses managed
`System.Diagnostics.Process`, and Win32 error codes are read with managed
`Marshal.GetLastWin32Error` (a wrapper over `GetLastError`). The functions below
are the complete set the tool depends on, grouped by the library they come from.

### kernel32.dll — process, memory, threads, launch, and the debugger loop

| Function | Used for |
|---|---|
| `OpenProcess` | Open a target by PID with exactly the rights a step needs (query + read, or also write/operation for instrumentation). The entry point for both read-only discovery and capture. |
| `CloseHandle` | Release process, thread, and snapshot handles. |
| `ReadProcessMemory` | The one host-side read primitive: instruction bytes for disassembly, module headers and `.pdata` for unwinding, the PEB for the image base, and argument-pointed memory for string dereferencing. Returns nothing for a bad pointer, so it can never crash the target. |
| `WriteProcessMemory` | Write the capture stub, the trampoline, and the entry patch into the target — and restore the original entry bytes when a hook is removed. |
| `IsWow64Process2` | Determine the target's actual machine (x86 / x64 / arm64) independent of the host, to choose the right decoder and confirm the host can instrument it. |
| `VirtualAllocEx` | Allocate memory *inside the target* for the per-function capture stubs, the trampolines, and the record ring buffer. |
| `VirtualFreeEx` | Free those target allocations when a session detaches. |
| `VirtualProtectEx` | Make the entry page writable to apply or restore a patch, then put protection back. |
| `FlushInstructionCache` | Flush the target's instruction cache after writing code, so the CPU executes the new bytes — mandatory after every patch/trampoline write. |
| `VirtualAlloc`, `VirtualProtect`, `VirtualFree` | The in-process equivalents, used only by the codegen self-test, which builds and hooks a throwaway function inside the app's own process. |
| `GetCurrentProcess` | The current-process pseudo-handle, used by the self-test memory path and by privilege adjustment. |
| `CreateToolhelp32Snapshot`, `Thread32First`, `Thread32Next` | Enumerate the target's threads so every one of them can be frozen for the duration of a patch. |
| `OpenThread`, `SuspendThread`, `ResumeThread` | Suspend each target thread at an instruction boundary while installing or removing a hook (so no thread is mid-instruction in the bytes being rewritten), then resume them. |
| `CreateProcessW` | Launch an executable either suspended (`CREATE_SUSPENDED`, for the startup trace) or under a debugger (`DEBUG_PROCESS`, for DLL-at-load capture and child-follow). |
| `InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute`, `DeleteProcThreadAttributeList` | Build the one-entry proc-thread attribute list that carries a process-creation **mitigation policy**, so a launched target can have bottom-up + high-entropy **ASLR forced off** for reproducible module bases. Used only when the **Disable ASLR** toggle is on; the target is then created with `EXTENDED_STARTUPINFO_PRESENT`. |
| `WaitForDebugEvent`, `ContinueDebugEvent` | The debugger event loop — wait for create-process / load-DLL / exit / exception events and continue the debuggee. Drives DLL-at-load capture and following a process tree. |
| `DebugActiveProcessStop` | Detach the debugger cleanly, leaving the (possibly still-running) tree alive. |
| `DebugSetProcessKillOnExit` | Ensure detaching the debugger doesn't take the debuggee down with it. |
| `GetFinalPathNameByHandleW` | Resolve the on-disk path behind the file handle handed out with a `LOAD_DLL` debug event, to recognize the DLL being targeted. |

### psapi.dll — module enumeration

| Function | Used for |
|---|---|
| `EnumProcessModulesEx` | List every module loaded in the target, including both 32- and 64-bit modules. |
| `GetModuleFileNameExW` | Get each module's full path and name. |
| `GetModuleInformation` | Get each module's base address and image size, which is what the address-to-module map is built from. |

### ntdll.dll — process information block

| Function | Used for |
|---|---|
| `NtQueryInformationProcess` | Read `PROCESS_BASIC_INFORMATION` to find the PEB, so the ASLR-relocated image base can be read from `PEB->ImageBaseAddress`. This is what makes a suspended launch's entry-point address reliable. |

### advapi32.dll — token privileges

| Function | Used for |
|---|---|
| `OpenProcessToken` | Open the app's own process token to adjust its privileges. |
| `LookupPrivilegeValue` | Resolve the LUID for `SeDebugPrivilege` by name. |
| `AdjustTokenPrivileges` | Enable `SeDebugPrivilege` so the tool can open and instrument other processes — required once at startup even when running elevated. |

### dbghelp.dll — local symbols

| Function | Used for |
|---|---|
| `SymSetOptions` | Configure the symbol handler: undecorate names, defer loads, no prompts, and strictly *local* lookup (no symbol server, so attaching can't hang downloading PDBs over the network). |
| `SymInitializeW` | Initialize DbgHelp against the target process handle. |
| `SymLoadModuleExW` | Register a module so its local PDB (or export table) can be queried. |
| `SymFromAddrW` | Resolve an address to a symbol name and displacement — used to name internal `sub_XXXX` functions when a matching PDB is present, accepting only exact entry-point hits (displacement 0). |
| `SymCleanup` | Tear down the symbol handler when the naming pass is done. |

---

## Project layout

```
Cda.Modern/
├─ Cda.Core/                 engine (no WPF)
│  ├─ Cpu/                   ICpuArchitecture, X86/X64Architecture, decoder, conventions
│  ├─ Engine/                instrumentation: InlineHook + CaptureStub (entry hook + stack
│  │                         snapshot), CaptureBuffer (ring) + RingBuffer (decoder),
│  │                         CaptureSession, CallSiteScanner, StartupPlan (candidate +
│  │                         leaf-primitive filtering), StackUnwinder (x64 .pdata),
│  │                         ApiImportScanner + ApiSignatures, DebugLoadCapture,
│  │                         ChildFollowCapture, CaptureCondition, CaptureController,
│  │                         StringScanner (strings + code cross-references),
│  │                         SymbolResolver, TraceArchive, TraceCsvExport, TraceComparison,
│  │                         LiveSession, self-tests
│  ├─ Memory/                IMemorySource, BufferMemorySource, MappedFileMemorySource
│  ├─ Model/                 CallRecord, ModuleInfo / TracedFunction / TraceDataset, Dereference
│  ├─ Pe/                    PeImage (parse, exports/imports/sections, RVA↔VA↔file-offset)
│  └─ Process/               TargetProcess, ProcessList, ModuleMap, SuspendedProcess,
│                            ThreadSuspender, Privileges, RemoteMemory, NativeMethods (P/Invoke)
└─ Cda.App/                  WPF UI (net8.0-windows, x64;x86, Per-Monitor v2 DPI, requireAdministrator)
   ├─ App.xaml(.cs)          theme (single source of truth) + global exception handling
   ├─ MainWindow.xaml(.cs)   toolbar, layout, engine orchestration, poll loop, runaway unhook
   ├─ UI/                    FunctionListView, CallListView, CallersView (caller tree),
   │                         CallStackView (per-call chain), HexView, StringsView
   │                         (strings + xrefs), ProcessPickerWindow, CompareWindow (trace diff)
   ├─ Visualization/         CallGraphView (butterfly + diff overlay), TraceDiffChart
   │                         (diverging diff bars), PlaybackBar (timeline), VisualTheme
   ├─ Model/                 CallGraphModel (+ neighborhood aggregation), GraphDiff (edge-diff
   │                         butterfly neighborhoods)
   └─ Demo/                  DemoDataSource (synthetic trace for offline UI work)
```

See **`ARCHITECTURE.md`** for the deeper design notes (hook/trampoline layout,
the ring-buffer protocol, and the legacy-to-modern mapping).
