# Architecture

How the engine works: discovering functions, splicing inline hooks, capturing
calls through a lock-free ring buffer, and supporting **both x86 and x64** targets
from one codebase. The UI is covered in `README.md`; this document is the engine
(`Cda.Core`).

## Two assemblies

- **`Cda.Core`** — engine, no WPF. Pure types + Win32 P/Invoke.
- **`Cda.App`** — WPF UI; depends on `Cda.Core`, never the reverse.

Within the engine the layers are: PE parsing (`Pe`) → process/memory model
(`Process`, `Memory`) → CPU abstraction + disassembly (`Cpu`) → instrumentation
(`Engine`). The data model (`Model`) is architecture-neutral and shared with the
UI.

---

## The x86/x64 strategy

The legacy tool wasn't merely *compiled* x86 — it was *designed* x86: arguments
read from `[ebp+8]`, cdecl/stdcall cleanup detection, 5-byte `E8` call patching,
and a hand-written `fs:[0]` SEH chain were woven through the code. "Make it 64-bit"
is therefore a second engine, not a recompile.

Two things keep that from forking the whole codebase:

1. **`ICpuArchitecture`** (`CpuArchitectures.For(is64Bit)` → `X86Architecture` /
   `X64Architecture`) funnels the *inspection* and *discovery* differences —
   pointer size, argument layout, register-based argument recovery, and direct-call
   scanning — behind one interface. The target's bitness comes from
   `IsWow64Process2` on the *target* (in `TargetProcess.Is64Bit`), independent of
   the host.
2. **Per-architecture code generation** for the *instrumentation* itself lives in
   the `Engine` layer (`CaptureStub.BuildX86` / `BuildX64`, and `InlineHook`'s
   jump sizing), built with **Iced** rather than hand-assembled bytes. Iced decodes
   the target's instructions and re-encodes relocated ones, so the same hook logic
   serves both architectures.

### Host rule

The **x64 build is the universal host**: it instruments x64 targets and WOW64
(32-bit) targets. An x86 host cannot write code a 64-bit target will run, so that
direction is refused with a clear message. Build and run x64.

### x86 vs x64, concretely

| Concern | x86 | x64 |
|---|---|---|
| Integer args | all on stack (1st at `[esp+4]`) | RCX, RDX, R8, R9, then stack past 32-byte shadow space |
| Entry hook | 5-byte `E9` rel32 | `E9` rel32 if within ±2 GB, else 14-byte `FF 25` RIP-relative absolute jump |
| Stub register save | `pushfd` + `pushad` | individual `push` of touched regs + `pushfq` |
| Stub chain-back | direct `jmp` | `jmp qword ptr [rip+0]` + embedded 64-bit address (all regs restored first) |
| Frame pointer | usually present | not guaranteed; unwind-info driven |

---

## Discovery

`Pe/PeImage` parses headers, sections, exports, and imports, and converts between
RVA, VA, and file offset. `Engine/CallSiteScanner` walks code sections with Iced
(`ICpuArchitecture.FindDirectCalls`) collecting `(callSite, target)` edges and the
set of call targets, which become candidate functions.

For a **suspended** target (startup trace), the scan runs against the **on-disk
image**, not the frozen process: at creation most pages aren't faulted in yet, so a
memory scan badly under-reads (e.g. Rufus showed 8 functions mapped vs thousands
from the file). Direct calls are relative, so the file's call targets — as RVAs —
match the running image exactly; only the load base differs, by the ASLR delta,
which is added back (`DiscoverModuleSuspended`).

---

## Inline hook layout

`Engine/InlineHook` splices the entry of a function. It is **two-phase** to avoid a
race:

1. `Install(activate: false)` decides the patch length, builds the trampoline, and
   prepares (but does not write) the entry patch.
2. The caller writes the detour body (the capture stub) at the detour address.
3. `Activate()` writes the entry patch **last**, when everything it jumps to already
   exists, and flushes the instruction cache.

**Patch sizing.** The patch must cover whole instructions and be at least as long as
the entry jump it needs — 5 bytes for an in-range `E9`, 14 for the x64 absolute
`FF 25` form. Knowing the detour address up front means small functions aren't
over-stolen (which would overrun into the next function).

**Trampoline.** The stolen instructions are relocated with Iced's `BlockEncoder`
(fixing up RIP-relative and branch displacements), followed by a jump back to
`target + patchLen`. Calling the trampoline runs the original prologue and returns
into the function body.

**Safety guards.** `InlineHook` refuses a site if a clean instruction-aligned patch
can't be decoded, or if any branch in the function's opening window targets *inside*
the patch region (a loop back into our jump would crash the target). `Remove()`
restores the original bytes.

---

## Capture stub

`Engine/CaptureStub` generates the detour body written at each hooked entry. On every
call it claims a ring slot, records the call, restores state, and chains to the
trampoline. It is generated for the exact address it's written to (absolute targets
are embedded), and exists in `BuildX86` / `BuildX64` forms.

**Record layout** (little-endian; matches `RingBufferReader.Decode`). The record is
variable-length: a fixed header, then the integer args, then a fixed-depth stack
snapshot, then a host-filled dereference payload.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | timestamp (`rdtsc` ticks) |
| 8 | 8 | source — return address (caller) |
| 16 | 8 | destination — hooked entry (callee) |
| 24 | 8 | stack pointer at entry |
| 32 | 4 | argCount |
| 36 | 8 × argCount | integer args, each zero-extended to u64 |
| 36 + 8·argCount | 4 | stackSlots (always `CaptureStub.StackSlots`) |
| 40 + 8·argCount | 8 × stackSlots | stack snapshot from entry SP upward, zero-extended |
| 40 + 8·argCount + 8·stackSlots | 4 | derefCount (0 in-target; filled host-side) |
| … | derefCount × | dereference: u32 argIndex, u32 kind, u32 dataLen, u8[dataLen] |

```
RecordSize = 36 + argCount*8 + 4 + StackSlots*8 + 4   (before host dereferences)
```

`CaptureStub.StackSlots` is **64** (512 bytes on x64, 256 on x86). For the usual
`argCount = 4`, that makes a fixed record of **588 bytes** before any dereference
payload — the figure the capture Self-test reports. A 65,536-slot ring is therefore
~38 MB in the target. The stack snapshot is what lets the host walk back past
runtime/CRT wrapper frames to the program's own caller (see *Caller attribution*
below) **and** recover string arguments that sit past the captured integer args (see
*Capture session lifecycle*); raising `StackSlots` deepens both at a linear memory
cost. **Because it changes the record format, re-run the capture Self-test after
changing it** — the 588-byte figure is the end-to-end check that the stub writes and
the reader decodes the same layout.

The stub saves flags + GP registers (so the function sees its entry state intact),
claims a slot with `lock xadd` on the control block's `claimSeq`, masks to a slot
index (`seq & (slotCount-1)`), writes the fields (including copying `StackSlots`
words from the entry SP upward), restores, and jumps to the trampoline. x64 reads
the first four args from the saved RCX/RDX/R8/R9 slots and the rest past the shadow
space. There is **no bounds branch** — the power-of-two slot count makes the index
always valid.

The in-target stub writes `derefCount = 0`; the host fills the dereference payload
after the fact (see *Capture session lifecycle*), so no pointer-walking logic lives
in the target.

---

## Ring buffer protocol

`Engine/CaptureBuffer` is an in-target, lock-free ring plus a 16-byte control block,
both allocated in the target's address space.

```
control block (16 B): u32 magic 'CDAR' | u32 slotCount | u32 claimSeq | u32 recordSize
data: slotCount × recordSize, slotCount rounded up to a power of two
```

Each hooked thread claims a slot by atomically incrementing `claimSeq`. The host
remembers the last sequence it drained; `DrainSince(ref readSeq, out recordsLost)`
copies only records claimed since then — in one or two reads to handle wrap-around —
then advances `readSeq`, so nothing is dropped at poll boundaries. The subtraction
`claim - readSeq` is unsigned and therefore wrap-safe. If the writer got more than a
full ring ahead (lapping), only the freshest `slotCount` records survive and the rest
are reported as `recordsLost`. A short read of the control block (e.g. the target
exited) returns empty rather than misreading a zero counter.

The ring is sized so a hooked function can't lap the reader between 100 ms polls.
At the defaults (65,536 slots × a 588-byte record) that is ~38 MB in the target. The
byte size is computed in 64-bit and bounded by a **256 MB ceiling** — a larger record
(a deeper `StackSlots` snapshot) or a big `bufferRecords` drops the slot count to fit
rather than overflow the 32-bit allocation size, which would otherwise hand the stub a
too-small buffer it then writes past (it indexes up to `slotCount-1` with no bounds
check).

---

## Capture session lifecycle

`Engine/CaptureSession.Start(pid, functions, maxFunctions, bufferRecords, …)`:

- Opens the target, allocates the control block + ring (`CaptureBuffer.Create`).
- For each chosen function, **inside a `ThreadSuspender`** (all target threads frozen
  so none is executing the bytes being spliced): allocate a stub region →
  `InlineHook.Install(activate: false)` → `CaptureStub.Build` into the stub → flush →
  `InlineHook.Activate()`.
- Reports how many were instrumented/skipped and the first error.

`Poll()` calls `DrainSince`, decodes the raw records (`RingBuffer`), and **enriches
dereferences host-side**: the in-target stub records only raw integer/pointer values
(derefCount 0) to stay tiny and safe; the host then reads pointed-to memory with
`ReadProcessMemory` to recover strings/buffers. This keeps no string-walking logic
inside the target.

Dereferencing isn't limited to the few integer args the stub records. Beyond those,
the host also mines the **stack snapshot** for later positional arguments — a string
passed past the recorded slots (very common: x86 passes *every* argument on the
stack, and x64's 5th argument onward sits past the shadow space) would otherwise
"not show". Since the snapshot is copied from the entry SP upward, `snapshot[0]` is
the return address and argument *i* lives at `snapshot[i+1]` on both architectures.
The host walks the **whole** snapshot — there is **no fixed arg-count cap**, so a
string at arg11, arg20, … is still found. What bounds the scan is the string's own
**NUL terminator**, not an arity: a word is surfaced only when it points at a
printable, NUL-terminated run (`Classify`), which rejects return addresses and the
non-string words a frame holds. The reach is the snapshot depth
(`CaptureStub.StackSlots` words). No extra bytes are captured in the target — the
snapshot is already there for caller attribution. The cost of removing the cap is
that a deep caller-frame word that genuinely points at a string can occasionally
surface as a high-numbered argument.

`Dispose()` removes the hooks (restores original bytes) but **deliberately leaks** the
stub, trampoline, and ring allocations: a target thread could be mid-stub when we
detach, and freeing that memory would be a use-after-free. Leaking a few pages per
session is the safe trade.

---

## Caller attribution

A captured call names only its immediate return address. To answer *which function
in your program* triggered a call — even when it went through several CRT/runtime
wrapper frames — the host walks the per-record **stack snapshot** (the `StackSlots`
words copied from the entry SP upward).

Two strategies run and the deeper result wins:

1. **Heuristic word-scan.** Walk the snapshot word by word, keep those that fall in
   one of the program's own (non-Windows) modules *and* look like real return
   addresses — validated by reading the bytes just before the target and checking
   for a `call` opcode (`E8` rel32, or `FF /2`). The literal return address is
   trusted; deeper words must pass the call-site check so stack *data* isn't
   mistaken for a frame.
2. **Exact x64 `.pdata` unwinding** (`Engine/StackUnwinder`). On x64, every
   non-leaf function has `RUNTIME_FUNCTION` + `UNWIND_INFO` describing its prologue.
   The unwinder reads those to compute each frame's size and walk return addresses
   precisely, reaching app callers the word-scan misses through opaque runtime
   frames.

Each return address is floored to its enclosing discovered function (a binary search
over the app's sorted entry points, same-module checked) and consecutive duplicates
are collapsed. The result feeds two views: the per-call **Call stack** (one record's
chain) and the **Called by** tree, which folds every call's chain into a global
reverse-edge map (`callee → {caller → count}`) so it composes paths *across* records
and reaches deeper than any single snapshot. The tree is depth- and node-bounded and
marks recursion.

---

## Polling off the UI thread

The capture poll runs on a 100 ms WPF `DispatcherTimer`, but the heavy work does not
run on the UI thread. Each tick hands the whole expensive part — draining + decoding
the ring, host-side dereference enrichment, *and* each record's caller-chain
extraction (stack unwinding + return-address probes) — to a worker via `Task.Run`,
and a `_polling` guard makes ticks non-reentrant (a tick is skipped if the previous
poll is still draining). The UI thread is left with only cheap dictionary folds and
the WPF row adds.

The worker touches only read-only or concurrently-safe state: the capture's own ring
handle, `ReadProcessMemory`, and the immutable `ModuleMap`. The caller-chain resolver
used on the worker (`MainWindow.CaptureChainResolver`) owns its *own* unwinder and
caches and a snapshot of the function-entry index, so it never touches UI-thread
fields; because only one poll runs at a time, those caches are single-threaded in
practice. Driving the timeline is also by reference — the graph model points at the
live list and only the tail window is refreshed — rather than re-sorting the whole
capture each tick, which previously pegged the UI during a startup burst.

---

## Candidate selection and runaway auto-unhook

A broad trace can only arm a bounded number of hooks, and the real threat to a
readable trace is a tiny utility called in a hot loop — a `char`/`string` primitive
that fires millions of times and laps the ring, starving every other hook. Two
mechanisms, one static and one runtime, keep those out.

**Static — `Engine/StartupPlan`.** Candidates are ordered by inbound call-site count
with the hottest few skipped (as before), but additionally **leaf primitives are
held back**: a function that makes no outbound call of its own and is either *tiny*
(estimated size at or under a small byte budget) or *widely used* (called from many
static sites). Size is estimated as the gap to the next discovered entry in the same
module, and that estimate is trusted only when the gap is present and plausible — a
missing or implausibly large gap is treated as *unknown* size, in which case the
high-fan-in signal alone decides. (This is what catches a diffuse flooder whose
size-by-gap looks large but is really a discovery hole after it.) Held-back
primitives are only drawn on to fill leftover budget on a small target,
least-referenced first. The same plan is shared by the suspended-launch, DLL-load,
and child-follow paths.

**Runtime — `MainWindow.CheckRunaway`.** Static signals can't perfectly predict
runtime hotness, so a flooder that slips into the hooked set is dropped adaptively.
Each poll, two triggers can unhook a single callee (via
`CaptureSession.UnhookFunction`, which freezes the target with a `ThreadSuspender`
and restores the original entry bytes): a **cumulative ceiling** — any hooked callee
whose total recorded calls cross a hard limit, which runs every tick and catches a
*diffuse* runaway that never dominates one batch — and a **per-batch dominance**
check — a callee both dominating a heavy batch and past a lower call floor, which
catches a *bursty* runaway earlier. An unhooked function stays in the views with the
count it reached; the rest of the trace keeps recording. A user-focused
single-function capture is never auto-unhooked.

---

## Startup trace (launch suspended)

`Process/SuspendedProcess` creates the target with `CREATE_SUSPENDED` and reads its
image base from the PEB. `MainWindow.OnLaunchCapture` then:

1. Discovers functions from the on-disk image and rebases to the actual load address.
2. If fewer than ~16 functions are visible pre-run, treats the target as **packed**
   (only the unpacker stub is exposed) and does *not* hook before run — hooking the
   unpacker would corrupt unpacking. It traces the real code after startup instead.
3. Otherwise picks a broad candidate set with `Engine/StartupPlan` (order by inbound
   call frequency, skip the hottest few, and hold back leaf primitives — see
   *Candidate selection and runaway auto-unhook*), arms them, attaches the crash
   watch (below) **before** the first instruction runs, and only then calls `Resume()`.
4. After the program is running it attaches a read-only `LiveSession` for the hex view
   and click-to-focus, and — for the packed/fallback path — runs a post-start broad
   trace of the now-unpacked code.

### Crash watch (`Engine/DebugCrashWatch`)

A spliced entry hook can still crash a *valid* function — one whose `.pdata` entry
passes the `EntryPointGuard` but which, e.g., checksums its own `.text` or is reached
in a way the relocated prologue disturbs. Historically the startup trace ran the
target **free** (`CREATE_SUSPENDED` + `ResumeThread`, no debugger), so such a fault
killed it with the cause invisible — only a `0xC0000005` exit code survived.

`Engine/DebugCrashWatch` closes that gap. After the hooks are armed but before the
main thread is resumed, it `DebugActiveProcess`-attaches a debugger on a dedicated
thread and pumps the target's debug events. It swallows the attach breakpoint, steps
past first-chance breakpoints (a debugger-rendezvous `int3` runs only because we
attached, and isn't a crash), hands ordinary exceptions back to the program, and on a
genuine fault formats it with `DebugExceptionInfo` (faulting `module+0xRVA`, access,
instruction bytes, integer registers) and snapshots the crashing thread's stack — all
while the target is frozen at the event.

The host then *attributes* the fault to a culprit hook, strongest signal first: the
fault landed in a hook's own generated code (`CaptureSession.OwningHook` checks each
entry/stub/trampoline footprint), else it is inside a hooked function's body, else the
innermost hooked function still on the crashing stack (each candidate stack word
validated as a real return address — a `call` ends just before it — so a stray
code-looking data word can't implicate an innocent hook). The fault and the pinned
hook are **reported to the diagnostic log, and the capture stops** — it does *not*
relaunch the target. To trace past the offending hook, exclude it with the
`CDA_HOOK_RANGE` bisection (drop a `skip:take` range file and re-launch) and halve
toward the culprit by hand. A deferred fault can manifest *across a module boundary* —
a hook in the main image corrupts state a later-loaded DLL dereferences, by which
point the corrupting hook has already returned and is on no stack — so attribution is
best-effort; when it can't pin a single hook it says so, and the range bisection is
the fallback.

## DLL-at-load (capture from DllMain)

`Engine/DebugLoadCapture` launches a host (default `rundll32` of the matching bitness,
or a user-chosen EXE) under a Win32 debug loop (`DEBUG_ONLY_THIS_PROCESS`) on a
dedicated thread. On the `LOAD_DLL_DEBUG_EVENT` whose path matches the target DLL, it
hooks the DLL **while the loader is frozen at the debug event** — before `DllMain`
runs — then continues all events. This is how a DLL's own initialization is captured.

## Call-surface capture from startup (`LaunchApiCapture`)

`Engine/LaunchApiCapture` captures the calls a program makes (or receives) **during
its own startup**, which the attach-time `ApiImportScanner` + `CaptureSession` path
(MainWindow's *Capture Windows API* / *Capture imports (IAT)*) cannot: by the time
you attach to a running process its startup is over, those calls have already
happened, and the log shows nothing.

It cannot reuse the suspended-launch trick the EXE startup trace uses, for a
concrete reason: at `CREATE_SUSPENDED` the Windows loader has not run, so
kernel32/user32/… are not mapped and the **import-address table is not yet bound** —
there is nothing to resolve to a live entry or to hook. So it launches the target
under a debugger (`DEBUG_ONLY_THIS_PROCESS`, on the dedicated thread every debug loop
in this engine uses) and hooks at the **initial loader breakpoint**: the first
`EXCEPTION_BREAKPOINT`. That breakpoint is delivered *after* the loader has mapped
every static dependency, run their `DllMain`s, and bound the IAT, but *before* the
program's own entry point executes — every thread frozen, imports resolved, no app
code run. At that instant it:

1. attaches a read-only `TargetProcess`, enumerates modules into a `ModuleMap`, and
   discovers the chosen surface against the now-resolved tables — `ApiImportScanner`
   for the program's imports (inline `Discover` or slot-based `DiscoverImportSlots`),
   or `ExportScanner.Discover` for the functions the program's **own** modules export;
2. installs the hooks with `CaptureSession.Start` (inline splice of the resolved entry
   points — used for both imported APIs and own-module exports) or
   `CaptureSession.StartIat` (overwrite the import slots — data only, never `.text`,
   so an anti-tamper target that checksums its code is captured);
3. raises `Hooked` to the UI with the session + dataset (the surface's modules as
   nodes — the OS DLLs for imports, the app's own modules for exports) + the full
   `ModuleMap` (so both ends of a call resolve), then continues the debuggee.

The **exports** surface is the mirror of imports: `ExportScanner` walks the export
directory of each app module (skipping anything under `\Windows\`, and skipping
*forwarder* exports whose code lives in another DLL), resolving each export to
`module base + RVA`. Because an export is an authoritative function entry, that set
needs none of the call-site discovery heuristics the startup trace uses and is always
safe to splice. It hooks calls *in* to the app's public functions, where the import
surface hooks calls *out* to the OS.

Like `DebugLoadCapture` it keeps pumping after the hooks are armed: the first
breakpoint is swallowed (it is the loader's), a later int3 or hardware fault is
reported with `DebugExceptionInfo` (faulting `module+0xRVA`) and handed back to the
program, and `EXIT_PROCESS` ends the loop. The ring is drained by the UI's ordinary
100 ms poll through the session's own handle, concurrently with the debug loop — the
same arrangement the DLL-at-load capture uses. The hooked set is bounded
(`ApiTraceFunctions`) and the same ultra-hot primitives (critical-section / heap /
last-error) are skipped, exactly as in the attach-time form, since both share
`ApiImportScanner`.

## Child-process follow (instrument a tree)

`Engine/ChildFollowCapture` launches an executable under a `DEBUG_PROCESS` debug loop
(on a dedicated thread) that follows every process the target spawns. On each
`CREATE_PROCESS_DEBUG_EVENT` it instruments the new process at creation — frozen
before its code runs — using the same suspended-discovery + `StartupPlan` path as
"Launch & capture", so each child is traced from its own first instruction. An
optional filter skips OS/system processes (those under the Windows directory) so a
tree rooted in an app isn't drowned by service children. Each instrumented process
becomes a selectable target in the UI with its own dataset and a bounded ring of
retained records; selecting one drives the single-target views from its data while
the others keep recording in the background. A child has no live read-only session,
so its caller frames come from the stack snapshots (as in offline review) rather than
live `.pdata` unwinding.

## Strings + cross-references

`Engine/StringScanner` mines a module's printable strings and resolves their code
cross-references — the static counterpart to the call-graph discovery, against the
same on-disk image. It runs in two passes over the file (in preferred-base space,
like `CallSiteScanner.ScanFileImage`; the caller rebases the results by the ASLR
delta the way it does the discovered functions):

1. **Extract.** Every section with raw bytes is scanned for runs of printable
   characters — ASCII (`0x20–0x7E`) and UTF-16LE (printable byte, zero byte) —
   of at least a minimum length. An ASCII run must end in a **NUL terminator** to
   count (the definition of a C string): a printable run of *code* bytes in a
   `.text` section is almost never followed by `0x00`, so this drops that junk —
   which otherwise outnumbers the real strings ~5:1 and, on a large image, would
   exhaust the result cap and crowd the genuine `.rdata` strings out entirely —
   while keeping real literals (the compiler always NUL-terminates them) wherever
   they live. Executable sections are still scanned: compilers place read-only
   literals in `.text`, and some binaries merge `.rdata` into it, so the literals
   live there. The interleaved zero bytes of a wide string break it into length-1
   ASCII runs, so the two passes never double-count.

2. **Attribute.** Each executable section is disassembled with Iced; for every
   instruction operand that is a plain absolute or RIP-relative *data* reference
   (an x64 `lea reg,[rip+x]`, an x86 `push offset` / absolute `mov` — stack/based
   and indexed operands are ignored) the referenced address is looked up against a
   sorted interval index of the extracted strings. A hit floors the instruction's
   address to its enclosing discovered function (the same predecessor binary search
   the caller attribution uses) and records that function on the string.

The UI lists the strings, searchable, and — for one selected — the functions that
reference it; activating either jumps the rest of the UI to that function through
the ordinary click-to-focus path. Code bytes that happen to read as text are
filtered by the length threshold and, by default, by hiding strings nothing
references; the result is the Strings-with-xrefs window of a disassembler, driven
by CDA's own static discovery.

## Conditional capture ("Capture only")

`Engine/CaptureCondition` parses a small filter expression (e.g. on callee name or
argument value). Every call is still recorded *in-target* — the filter is applied
host-side, dropping non-matching records as a poll batch is processed, before they're
logged, folded, or counted. It is the analysis-time form of a data-driven hook:
changing the expression affects subsequent polls without re-instrumenting.

---

## Process & memory model

- `Process/TargetProcess` — `OpenProcess` + `ReadProcessMemory`/`WriteProcessMemory`,
  module enumeration, `IsWow64Process2` bitness. Implements `IMemoryEditor`.
- `Process/ModuleMap` — binary-searchable address → `module+0xRVA` resolution.
- `Engine/CodeMemory` — `ICodeMemory` (allocate executable memory, read/write/flush)
  over either the local process (`LocalCodeMemory`, used by the self-tests) or a
  remote target (`RemoteCodeMemory`, `VirtualAllocEx` + `FlushInstructionCache`).
- `Process/Privileges` — enables `SeDebugPrivilege`; `Process/ThreadSuspender` and
  `SuspendedProcess` freeze/resume threads around splicing.
- `Memory/IMemorySource` — read-only address space abstraction the hex view and PE
  inspector consume; implementations are `BufferMemorySource` (a byte buffer) and
  `MappedFileMemorySource` (a memory-mapped file, for browsing large modules with no
  managed copy). `TargetProcess` is the live-process source.
- `Engine/StackUnwinder` — exact x64 `.pdata` / `UNWIND_INFO` stack walker used for
  caller attribution (see *Caller attribution*); per-instance and not thread-safe, so
  the poll worker is handed its own.
- `Engine/SymbolResolver` — resolves addresses to names via PDB symbols when
  available, enriching the otherwise export-only function labels.
- `Engine/TraceArchive` — saves/loads a captured trace to a `.cdatrace` file
  (modules, functions, and recorded calls) for offline review.

## Self-tests

`Engine/HookSelfTest` and `Engine/CaptureStubSelfTest` run in-process with no target,
against `LocalCodeMemory`, to validate the byte-exact pieces for the current build's
architecture: patch sizing + stolen-byte relocation + jump encoding, and the stub +
ring (one record per call, then chain to the trampoline). Run them after any codegen
change.

---

## Legacy → modern mapping

| Legacy (Function_Debugger / CDA) | Modern |
|---|---|
| Managed DirectX point/line/text renderer (`oVisMain`, `oVisLookup`) | `Visualization/CallGraphView` (WPF vector) |
| `oVisPlayBar` | `Visualization/PlaybackBar` |
| `oVisModuleManager` / `oVisModule` layout + lookup | `Model/CallGraphModel` (+ caller/callee aggregation) |
| `oSingleData` | `Model/CallRecord` |
| `Be.Windows.Forms.HexBox` | `UI/HexView` (on-demand `IMemorySource`) |
| bespoke length-decoder | Iced |
| hand-written x86 injection asm, call-site patching | `Engine/InlineHook` + `Engine/CaptureStub` (entry hooks, x86 **and** x64) |
| x86-only `[ebp+n]` argument reads | host-side dereference from captured register/stack values |
| `fs:[0]` SEH chain | not reintroduced; the stub is minimal and guarded at install time |

The one notable semantic change: the original patched **call sites**; this rewrite
patches **function entries**, which is architecture-uniform and avoids needing to
find and rewrite every caller.
