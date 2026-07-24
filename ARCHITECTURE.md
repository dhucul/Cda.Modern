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

The single **x64 build is the universal native host**: it instruments x64 targets
and WOW64 (32-bit) targets. Suspended PE32 launches query
`ProcessWow64Information` for PEB32 before reading `ImageBaseAddress`; using the
parallel native PEB would produce a bogus 64-bit base. Managed method discovery
is the exception: ClrMD's DAC attach cannot inspect a 32-bit .NET target from the
x64 CDA process, so use native capture modes for that target.

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
RVA, VA, and file offset. `Engine/CallSiteScanner` seeds Iced decoding from the PE
entry point, exports, AMD64 `.pdata` entries, and executable-section starts, then
recursively follows reachable calls and branches. It does not linearly reinterpret
embedded data after a return/jump as instructions. Direct-call targets become
candidate functions; `call $+next; pop` instruction-pointer idioms are rejected.
For AMD64, `.pdata` supplies known non-leaf entries and body ranges. Exact starts are
trusted and mid-body call targets are rejected, while targets outside those bodies
remain eligible because leaf functions need no unwind entry. The hook guard applies
the same rule. File regions are clipped to both section raw data and the actual EOF,
so every listed static candidate has bytes the disassembly view can open.

`ModuleInfo` retains both the actual load base and the PE preferred image base. The
function list therefore presents live VA, static-disassembler VA, and RVA separately;
unnamed `sub_*` labels use the static-disassembler VA rather than an ASLR-dependent
live address. Trace archive v2 persists the preferred base while the reader remains
backward-compatible with v1 traces.

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
| 32 | 4 | argCount — **high bit** (`CaptureStub.KindReturn`) marks a *return* record |
| 36 | 4 | correlationId — the claim sequence; pairs a return record with its call |
| 40 | 8 × argCount | integer args, each zero-extended to u64 (args[0] is the *return value* in a return record) |
| 40 + 8·argCount | 4 | stackSlots (always `CaptureStub.StackSlots`) |
| 44 + 8·argCount | 8 × stackSlots | stack snapshot from entry SP upward, zero-extended |
| 44 + 8·argCount + 8·stackSlots | 4 | derefCount (0 in-target; filled host-side) |
| … | derefCount × | dereference: u32 argIndex, u32 kind, u32 dataLen, u8[dataLen] |
| payload end | 4 | commitSequence — the claimed sequence, published after the payload |
| payload end + 4 | 4 | commitSequenceInverse — bitwise complement of commitSequence |

```
RecordSize = 40 + argCount*8 + 4 + StackSlots*8 + 4 + 8   (payload + commit footer)
```

`CaptureStub.StackSlots` is **64** (512 bytes on x64, 256 on x86). For the usual
`argCount = 4`, that makes a fixed record of **600 bytes**, including its commit
footer — the figure the capture Self-test reports. A 65,536-slot ring is therefore
~39 MB in the target. The `argCount` field carries a **kind flag** in its high bit
(so a value > 256 never collides with a real arity, which the decoder already rejects)
and a **correlationId** follows it, so both a call and its later return decode through
the same fixed layout and pair up host-side. The stack snapshot is what lets the host walk back past
runtime/CRT wrapper frames to the program's own caller (see *Caller attribution*
below) **and** recover string arguments that sit past the captured integer args (see
*Capture session lifecycle*); raising `StackSlots` deepens both at a linear memory
cost. **Because it changes the record format, re-run the capture Self-test after
changing it** — the 600-byte figure is the end-to-end check that the stub writes and
the reader decodes the same layout.

The stub saves flags + GP registers (so the function sees its entry state intact),
claims a slot with `lock xadd` on the control block's `claimSeq`, masks to a slot
index (`seq & (slotCount-1)`), invalidates the slot's old footer, writes the fields
(including copying `StackSlots` words from the entry SP upward), then publishes the
sequence/complement footer, restores, and jumps to the trampoline. x64 reads
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
copies the range twice and advances through only the contiguous slots whose
sequence/complement commit footer is stable in both snapshots. A claimed slot still
being written therefore remains pending for the next poll. The subtraction
`claim - readSeq` is unsigned and therefore wrap-safe. If the writer got more than a
full ring ahead (lapping), only the freshest `slotCount` records survive and the rest
are reported as `recordsLost`. A short read of the control block (e.g. the target
exited) returns empty rather than misreading a zero counter.

The ring is sized so a hooked function can't lap the reader between 100 ms polls.
At the defaults (65,536 slots × a 600-byte record) that is ~39 MB in the target. The
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
run on the UI thread. Each tick drains + decodes the ring on a worker, briefly returns
to the UI thread to remove any detected runaway hook, then sends host-side dereference
enrichment and caller-chain extraction (stack unwinding + return-address probes) back
to workers. Removing the runaway before those stages prevents it from continuing to
lap the ring throughout thousands of cross-process reads or a large `ResolveAll` pass. A
`_polling` guard makes ticks non-reentrant (a tick is skipped if the previous poll is
still draining).

The UI folds the resulting dictionaries. The Calls grid uses ordinary collection
notifications for small batches (preserving selection, scrolling, filtering, and
sorting), but collapses a genuinely large update into one collection reset and
restores any retained selection afterward. Its visible row cache keeps the newest
5,000 calls by default (user-configurable); timeline navigation finds its record in
the full trace first and only synchronizes a grid row when that row is still retained.
The full trace also backs export/copy, caller totals, and per-function counts.

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
Immediately after each ring drain—and before dereference enrichment or caller-chain
resolution—two triggers can unhook a callee (via
`CaptureSession.UnhookFunction`, which freezes the target with a `ThreadSuspender`
and restores the original entry bytes): a **cumulative ceiling** — any hooked callee
whose total recorded calls cross a hard limit, which runs every tick and catches a
*diffuse* runaway that never dominates one batch — and a **per-batch dominance**
check — a callee both dominating a heavy batch and past a lower call floor, which
catches a *bursty* runaway earlier. Safety totals are accumulated from raw records,
independently of the display-only `Capture only` filter. A batch invalidated by
**Clear calls** is not allowed to remove a hook. An unhooked function stays in the
views with the count it reached; the rest of the trace keeps recording. A focused
single-function capture does not use dominance (one hook would always be 100%), but
its hook is removed at a 20,000-decoded-call threshold and sooner if its smaller ring
laps. Batch draining/finalization can retain a small in-flight tail beyond the threshold.
When an auto-unhook removes the final hook, the session finishes automatically rather
than leaving a zero-hook poll timer running.

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

## Hardware-confirmed dialog gating branch

The Dialogs tab names the conditional jump that gated a dialog call. `Engine/DialogBranchAnalyzer`
picks it *statically* from code geometry, but that is a **guess** when several jumps route into the
box path (e.g. an `je` entry-gate above a nearer `jbe`/`ja`): geometry cannot know which one the CPU
actually took. `Engine/DialogBranchConfirmer` replaces the guess with **runtime ground truth**, on
the launch dialog path (which owns a live debugger), with no kernel driver and no Intel PT.

`DialogBranchAnalyzer.CollectCandidates` returns the nearest few conditional branches above the call
(each tagged `SkipOver` / `EntryGate` / `IntoPath` — the same geometry the single-pick selector uses).
`LaunchApiCapture` arms up to four of them in the CPU's **hardware execute breakpoints (DR0–DR3)** on
every thread — reusing the `ThreadContextX64` DR machinery the hardware-breakpoint capture already
proves. A DR execute breakpoint faults **before** the instruction runs, so the thread's EFLAGS at the
fault are exactly the flags that `Jcc` will consume, and it fires **only** on instructions actually
executed — so a branch skipped by an earlier taken jump is never even seen, and cannot be mis-scored.
On each `#DB` the loop evaluates the branch's real taken/not-taken from EFLAGS
(`DialogBranchConfirmer.Taken`, a complete per-mnemonic table incl. `jcxz`/`loop`), decides whether
that direction **routes into the dialog** (a `SkipOver` routes in when *not* taken, an `EntryGate`/
`IntoPath` when taken), and steps over the breakpoint with the resume flag so it stays armed. The
decisive branch — nearest routing-in — is reported through `BranchConfirmed`; the UI upgrades the
dialog row in place from the static guess to `… (→ dialog | not taken) [confirmed]`.

The branch has already executed by the time the dialog hook fires, so confirmation lands the **next**
time the caller runs (the first dialog shows the static guess, then upgrades). Correlation is by
**call site** — the candidates are unique to one code path, so no thread id is needed. DRs are cleared
on every thread before detach (they survive a lost debugger, else the target faults). Both x64 and
**WOW64 (32-bit) targets** are supported: `ThreadContextWow64` (over `WOW64_CONTEXT` via
`Wow64Get/SetThreadContext`, with the 32-bit `#DB` arriving as `STATUS_WX86_SINGLE_STEP`) sits behind
the same `IThreadContext` seam, so the probe logic is bitness-neutral. Validated by
`Engine/DialogBranchConfirmerSelfTest` (the condition table + the decision state machine, incl. the
`je`-guess→`ja`-confirmed case) and cross-process launch runs against both an x64 and a 32-bit target.

## Intel PT first-occurrence confirmation

The DR path above confirms the gating branch on the caller's *next* run (a DR breakpoint
can't see a branch that already executed). **Intel Processor Trace** is always-on branch
recording, so the gate can be confirmed on the **first** occurrence, retroactively.
`Engine/IntelPt` drives the Windows inbox PT driver (`ipt.sys`, device `\\.\Ipt`): it starts
the inbox `Ipt` service (elevated) to expose the device, then per-process traces the launched
target from startup (`IptStartProcessTrace`, user-mode, timing disabled). The IOCTL interface
is undocumented (reverse-engineered by WinIPT, verified byte-for-byte): `IPT_INPUT_BUFFER`
0x30 with `BufferMajorVersion@0=1`, `InputType@8`, union at `0x10`; the read returns
`IPT_TRACE_DATA` + packed per-thread `IPT_TRACE_HEADER{ThreadId, RingBufferOffset, TraceSize}`
+ each thread's circular PT-packet buffer.

`Engine/PtDecoder` turns a trace into a confirmation. It parses the per-thread framing,
unwraps each circular buffer to chronological order, and decodes the PT packet stream (PSB
sync, short/long **TNT** taken/not-taken bits, **TIP** with the last-IP compression). The
insight that makes this tractable — no full multi-module reconstruction or IP-filtering — is
that a dialog's argument setup has **no branches**, so the conditional branches executed
immediately before the `call dialog-API` transfer *are* the gating branches: find the most
recent **TIP whose target is the dialog API entry**, read the TNT bits right before it
(nearest-to-the-call first), map them onto the static candidate list, and let
`DialogBranchConfirmer.Resolve` pick the nearest routing-in gate — the same rule the DR path
uses. The result is raised on the same `BranchConfirmed` event, so the UI upgrade is identical.

`LaunchApiCapture` would try **PT first** and fall back to the DR path on a miss. **The PT
confirmation is currently DISABLED** (`EnablePtFirstOccurrence = false`): the scoped shortcut
above is only sound when *nothing else branches* between the gate and the call. On real /
obfuscated targets other branches execute in that window, so the "N TNT bits before the call =
the N candidates" mapping pins a bit to the wrong branch and can emit a **false** `[confirmed]`
for a branch that never executed — strictly worse than the DR path, which only ever reports an
*executed* branch. Making PT correct requires **full instruction-level control-flow
reconstruction** (decode every instruction from a PSB with a call stack for return compression,
attributing each TNT bit to its real branch address); until then confirmation is DR-only. The
device/decoder (`IntelPt`, `PtDecoder`) and the proven interface remain for that work. Validated
by `Engine/PtDecoderSelfTest` (synthetic buffer → `ja` not-taken) and a real-trace run — both of
which use the clean single-gate shape where the shortcut holds.

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

## Return-value capture

Optionally, each call also records what its function **returned** (`RAX`/`EAX`). The
entry stub is normally entry-only — it chains to the trampoline and the callee's `ret`
goes straight back to the real caller — so seeing a return means regaining control
*after* the callee runs. A per-thread TLS shadow stack (the textbook approach) isn't
usable here: Iced's fluent assembler can't emit a segment override (`gs:`/`fs:`) to
reach the TEB, and hand-encoding a branchy TLS block as raw bytes is too risky. Instead
each hook gets a **single return slot** guarded by an atomic `lock cmpxchg`:

1. On entry (when return capture is on), the stub tries to claim the hook's slot
   (0 → 1). If it **wins**, it stashes the real return address + correlationId in a
   per-hook return context and overwrites the on-stack return address so the callee
   returns into a shared **return stub**.
2. If it **loses** (a concurrent or recursive call already owns the slot), it does not
   redirect — so at most one outstanding return per hooked function is tracked at a
   time (concurrent/recursive returns are *sampled*, not all captured).
3. The return stub records the return value as a *return record* (kind bit set,
   correlationId = the call's), releases the slot, and resumes at the real caller —
   preserving `RAX`/flags (x64 uses volatile `r11` for the resume address; x86 reserves
   a stack slot and `ret`s to it, race-free since only one thread owns a hook's slot).

The slot mechanism itself is **safe**: an exception/tail-call that never returns just
leaves the slot owned (return capture quietly stops for that hook) — it never jumps to a
stale address.

**x64 exception safety.** While a call's return is redirected, its on-stack return address
points at the return stub, which has no `.pdata` unwind info — so a C++/SEH exception
unwinding *through* that live frame would make the table-based x64 unwinder mis-unwind and
crash. This is handled by a **first-chance vectored exception handler** installed in the
target (`CaptureStub.BuildReturnVehX64`, registered by `CaptureSession.TryRegisterReturnVeh`
via a one-shot remote thread calling `AddVectoredExceptionHandler`). On any exception, the
handler walks a registry of return contexts and restores every outstanding redirected
return address at/above the faulting SP to its real value (releasing the slot) *before* the
unwind proceeds, so the unwinder sees the correct address. Restoring a slot only
un-redirects that one call — never a crash or corruption — so no per-thread stack-bounds
check is needed and touching another thread's slot merely costs that call its return value.
Registration is verified through the remote thread's exit code; if it fails, x64 capture
stays entry-only rather than redirecting returns without an exception safety net. It is x64-only
(x86's chain-based SEH is unaffected). Validated by `CaptureVehSelfTest` (the fixup logic)
and a cross-process return-capture run. `CaptureSession.Poll` folds each return record into its originating call
(`ReturnValue`/`HasReturned`) by correlationId and drops it. Enabled with the
`captureReturns` flag on `CaptureSession.Start` (the "Capture returns" toggle);
`Engine/CaptureReturnSelfTest` validates the redirect/record/resume end to end.

## Managed (.NET) capture (`Cda.Managed`)

.NET assemblies are handled in a separate assembly, **`Cda.Managed`** (ILSpy's
`ICSharpCode.Decompiler` + ClrMD `Microsoft.Diagnostics.Runtime`), so those heavy
dependencies stay out of `Cda.Core` (Iced + P/Invoke only). `Pe/PeImage.IsManaged`
(optional-header data directory 14, the CLR header) routes a managed image away from
the native Iced scan, which would decode its IL/metadata `.text` as garbage.

- **Static** (`ManagedImage`): enumerate a file's methods (`System.Reflection.Metadata`),
  render a selected method's **IL** (`ReflectionDisassembler`) and decompiled **C#**
  (`CSharpDecompiler`) in the Disassembly pane, and extract embedded resources. Methods
  are surfaced in the function list by a *tagged* synthetic address
  (`0x4000_0000_0000_0000 | token`) that can't collide with a real address.
- **Live** (`ManagedMethodScanner`): the elegant part — managed methods reuse the
  **entire native hook pipeline**. ClrMD attaches passively (`DataTarget.AttachToProcess`,
  `suspend: false` — read-only, not a debugger, so it coexists with the write handle and
  `ThreadSuspender`) and reports each JIT-compiled method's **native code address**
  (`ClrMethod.NativeCode`). `CaptureSession.HookMore` then inline-hooks those addresses
  exactly like native functions — bypassing the `EntryPointGuard` (JIT code has no
  `.pdata`, and a JIT entry is authoritative) while keeping the codegen safety checks.
  Return-value capture applies unchanged. Methods JIT lazily and tiered compilation
  re-JITs to a new address, so a slow re-scan timer hooks newly-compiled methods (launch
  the target with `DOTNET_TieredCompilation=0` for stable addresses). x64 CLR uses the
  platform ABI (`this` in RCX), so the existing RCX/RDX/R8/R9 capture yields the useful
  integer/pointer/string args; struct/generic decoding is best-effort.

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
