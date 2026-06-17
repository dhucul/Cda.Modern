using System;
using System.Collections.Generic;
using Cda.Core.Cpu;
using Cda.Core.Model;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Active call recording in a live target. Allocates the ring buffer and a
    /// per-function capture stub in the target, installs entry detours on the
    /// requested functions, and drains captured records on demand.
    ///
    /// This is the cross-process counterpart of the in-process self-tests, using
    /// the exact same hook + stub codegen. It opens its own write handle (separate
    /// from the read-only discovery handle).
    ///
    /// First-cut limitations, called out honestly:
    ///   * a bounded number of functions are instrumented (mis-decoded sites are
    ///     skipped rather than risked);
    ///   * install and teardown freeze the target's threads to avoid patching a
    ///     running entry, but a thread created during that brief window isn't
    ///     covered;
    ///   * instrumentation memory is intentionally leaked on stop (a thread may
    ///     still be inside a stub), so it is reclaimed only when the target exits;
    ///   * records are drained from a lock-free ring sized so the writer cannot
    ///     lap the reader between polls; if it ever does, the oldest records are
    ///     overwritten and counted in <see cref="RecordsLost"/>.
    /// </summary>
    public sealed class CaptureSession : IDisposable
    {
        private const int StubBytesMax = 512;

        private readonly TargetProcess _process;
        private readonly RemoteCodeMemory _code;
        private readonly CaptureBuffer _buffer;
        private readonly List<InlineHook> _hooks = new();
        private readonly List<IatHook> _iatHooks = new();
        private ulong _tscBase;
        private bool _haveBase;
        private uint _readSeq;

        /// <summary>Records overwritten before a poll could read them (0 in normal use).</summary>
        public long RecordsLost { get; private set; }

        public bool Is64Bit => _process.Is64Bit;
        public int HookedCount => _hooks.Count + _iatHooks.Count;
        public int Pid => _process.Pid;
        public int ArgCount { get; }

        /// <summary>
        /// Addresses of the functions actually given an inline entry detour. Exposed
        /// for diagnostics and for the CDA_HOOK_RANGE bisection aid, so a crash can
        /// be narrowed to the exact culprit function.
        /// </summary>
        public IReadOnlyList<ulong> HookedTargets => _hooks.ConvertAll(h => h.Target);

        /// <summary>
        /// Non-null when CDA_HOOK_RANGE restricted which slice of the candidate list
        /// was hooked this run (a human-readable "skip=.. take=.. of .."); null in a
        /// normal full run. A bisection aid only.
        /// </summary>
        public string? HookRange { get; private set; }

        /// <summary>
        /// Always set by <see cref="Start"/>: a human-readable note of every range-file
        /// path that was checked and what it held, plus the env var — so a run makes it
        /// obvious where to drop the bisection file and whether it was picked up. This
        /// also confirms the build actually contains the range logic (if this line is
        /// missing from the log, an old binary is running).
        /// </summary>
        public string? HookRangeProbe { get; private set; }

        /// <summary>False once the target process has exited (so a poll can stop
        /// cleanly instead of silently draining nothing from a dead target).</summary>
        public bool IsTargetAlive => _process.IsAlive;

        /// <summary>The target's exit code once it has exited (false while running);
        /// a 0xCxxxxxxx value is an NTSTATUS crash code, not a normal exit.</summary>
        public bool TryGetTargetExitCode(out uint code) => _process.TryGetExitCode(out code);

        private CaptureSession(TargetProcess process, RemoteCodeMemory code,
            CaptureBuffer buffer, int argCount)
        {
            _process = process;
            _code = code;
            _buffer = buffer;
            ArgCount = argCount;
        }

        // Candidate locations for the bisection range file, checked in this order.
        // Several are tried so the file can be dropped wherever is convenient and is
        // found regardless of how CDA's TEMP is configured or how it was launched:
        //   1. next to the CDA executable, 2. the user profile root
        //   (C:\Users\<you>\cda_hook_range.txt), 3. %TEMP%.
        private static string[] HookRangeFilePaths()
        {
            var list = new List<string>();
            void Try(Func<string> f) { try { list.Add(f()); } catch { } }
            Try(() => System.IO.Path.Combine(AppContext.BaseDirectory, "cda_hook_range.txt"));
            Try(() => System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "cda_hook_range.txt"));
            Try(() => System.IO.Path.Combine(System.IO.Path.GetTempPath(), "cda_hook_range.txt"));
            return list.ToArray();
        }

        public static CaptureSession Start(
            int pid, IEnumerable<ulong> functions, int maxFunctions, int bufferRecords,
            out int instrumented, out int skipped, out string? firstError,
            IReadOnlyList<ModuleInfo>? knownModules = null)
        {
            var proc = TargetProcess.Attach(pid, forWrite: true);
            try
            {
                var memory = new RemoteMemory(proc);
                var code = new RemoteCodeMemory(proc, memory);
                var arch = CpuArchitectures.For(proc.Is64Bit);
                int argCount = 4;
                int recordSize = CaptureStub.RecordSize(argCount);

                var buffer = CaptureBuffer.Create(code, bufferRecords, recordSize);
                var session = new CaptureSession(proc, code, buffer, argCount);

                // Validate that each candidate is a real function entry before we
                // splice it. Discovery (CallSiteScanner) yields direct-call
                // *targets*, which are not always function entries — PIC
                // "call $+5" thunks, jump-table targets, and mid-function call
                // targets all slip in, and splicing an entry detour into one of
                // those corrupts the target's code and crashes it (the "some
                // programs, not all" failure). EntryPointGuard verifies entries
                // against the x64 .pdata function table (authoritative; its extents
                // also bound how far the splice may steal), with a PIC-idiom reject
                // + next-entry clamp where no table is available. Built here, at the
                // single choke point every capture path funnels through.
                var funcList = new List<ulong>(functions);

                // The guard's next-entry clamp (its x86 / no-.pdata fallback path)
                // must see EVERY candidate, not just a bisection slice — otherwise a
                // sliced run could compute a larger steal length for a function whose
                // real neighbour was sliced out, and patch it differently than a full
                // run would (distorting the bisection). So the guard is built from the
                // full set; only the iteration list below is sliced. (GetRange returns
                // a new list, so this reference keeps pointing at the full one.)
                var guardCandidates = funcList;

                // Bisection aid: a "skip:take" range restricts hooking to a slice of
                // the candidate list (by index, stable across runs because discovery
                // is deterministic), so a function that corrupts the target even when
                // cleanly hooked can be narrowed down WITHOUT recompiling — set the
                // range, re-run, halve toward the culprit. Read fresh from a file each
                // start (editable between runs, no restart), falling back to the
                // CDA_HOOK_RANGE env var. We ALWAYS record what we probed so the log
                // shows exactly where to drop the file. Accepts ':' '-' or ',' as the
                // separator; values are clamped.
                string? fileSpec = null, fileWhere = null;
                var probed = new List<string>();
                foreach (var p in HookRangeFilePaths())
                {
                    bool exists = false; string content = "";
                    try { exists = System.IO.File.Exists(p); if (exists) content = System.IO.File.ReadAllText(p).Trim(); }
                    catch { }
                    probed.Add($"{p} [{(exists ? (content.Length == 0 ? "blank" : "'" + content + "'") : "absent")}]");
                    if (fileSpec == null && exists && content.Length > 0) { fileSpec = content; fileWhere = p; }
                }
                string? envSpec = Environment.GetEnvironmentVariable("CDA_HOOK_RANGE");
                string? rangeSpec = fileSpec ?? (string.IsNullOrWhiteSpace(envSpec) ? null : envSpec);
                string rangeSource = fileSpec != null ? ("file " + fileWhere) : (rangeSpec != null ? "env" : "none");
                session.HookRangeProbe = "hook-range probe — " + string.Join(" | ", probed) +
                    $" ; env CDA_HOOK_RANGE={(string.IsNullOrWhiteSpace(envSpec) ? "unset" : "'" + envSpec + "'")}";

                if (!string.IsNullOrWhiteSpace(rangeSpec))
                {
                    var parts = rangeSpec.Split(new[] { ':', '-', ',' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length == 2
                        && int.TryParse(parts[0].Trim(), out int rSkip)
                        && int.TryParse(parts[1].Trim(), out int rTake)
                        && rSkip >= 0 && rTake >= 0)
                    {
                        int total = funcList.Count;
                        rSkip = Math.Min(rSkip, total);
                        rTake = Math.Min(rTake, total - rSkip);
                        funcList = funcList.GetRange(rSkip, rTake);
                        session.HookRange = $"skip={rSkip} take={rTake} of {total} (from {rangeSource})";
                    }
                    else
                    {
                        session.HookRange = $"(ignored malformed range '{rangeSpec}' from {rangeSource})";
                    }
                }

                // Build the module view the guard validates against. Live module
                // enumeration is authoritative ONCE the target's loader has run —
                // but in the suspended-launch path Start runs before the first
                // instruction, when the PEB loader list is still empty, so
                // EnumerateModules() returns nothing and every candidate would fall
                // through to the guard's weak heuristic (which doesn't reject
                // jump-table / mid-function / non-.pdata-entry targets — splicing one
                // of those is exactly what crashes the target with an int3). The
                // caller passes the already-known main module(s); their .pdata is
                // readable straight from the mapped image even pre-loader, so merging
                // them in restores the authoritative entry check.
                var guardModules = new List<ModuleInfo>(proc.EnumerateModules());
                if (knownModules != null)
                {
                    var have = new HashSet<ulong>();
                    foreach (var m in guardModules) have.Add(m.BaseAddress);
                    foreach (var m in knownModules)
                        if (have.Add(m.BaseAddress)) guardModules.Add(m);
                }
                var guard = new EntryPointGuard(proc, new ModuleMap(guardModules),
                    proc.TargetMachine == TargetProcess.PeMachineKind.X64, guardCandidates);

                instrumented = 0;
                skipped = 0;
                firstError = null;

                // Freeze the target while we patch entries so no thread is ever
                // executing the bytes we're overwriting.
                using (new ThreadSuspender(proc.Pid))
                {
                    foreach (ulong func in funcList)
                    {
                        if (instrumented >= maxFunctions) break;
                        try
                        {
                            // Skip anything that isn't a verified function entry —
                            // this is what stops the crashes. maxPatch bounds the
                            // steal length so a hook can't overrun into a neighbour.
                            if (!guard.IsHookable(func, out int maxPatch, out string? entryReason))
                            {
                                skipped++;
                                firstError ??= entryReason;
                                continue;
                            }

                            // The stub is the detour the entry E9 jumps to, so it
                            // must sit within +/-2GB of the function for that jump to
                            // be the 5-byte form (and not the 14-byte FF25 that forces
                            // a deep, fragile 14-byte steal). Allocate it near.
                            ulong stub = memory.AllocateNear(StubBytesMax, func);

                            // Build the trampoline + patch, but DO NOT arm the entry
                            // yet. TryInstall reports the routine "can't safely hook
                            // this site" outcomes (undecodable patch, branch into the
                            // patch, un-relocatable trampoline) without throwing, so a
                            // broad candidate sweep doesn't spray first-chance
                            // exceptions into a debugger on every start.
                            if (!InlineHook.TryInstall(arch, code, func, stub, activate: false,
                                    out var hook, out string? skipReason, maxPatch))
                            {
                                skipped++;
                                firstError ??= skipReason;
                                continue;
                            }

                            byte[] stubBytes = CaptureStub.Build(proc.Is64Bit, stub, func,
                                buffer.ControlAddress, buffer.DataAddress, hook!.Trampoline, argCount, buffer.SlotCount);
                            if (stubBytes.Length > StubBytesMax) { skipped++; continue; }

                            code.Write(stub, stubBytes);
                            code.Flush(stub, stubBytes.Length);

                            // Stub is fully written; now arm the entry detour.
                            hook.Activate();
                            session._hooks.Add(hook);
                            instrumented++;
                        }
                        catch (Exception ex)
                        {
                            // An unexpected failure (e.g. a cross-process write or
                            // allocation fault) — contained so one bad site never
                            // aborts the whole sweep.
                            skipped++;
                            firstError ??= ex.Message; // remember why the first one failed
                        }
                    }
                }

                return session;
            }
            catch
            {
                proc.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Start an IAT (import-address-table) capture: hook the given import slots
        /// by pointing each at a capture stub that records the call and then chains
        /// to the real function. Unlike <see cref="Start"/> this writes ONLY to the
        /// target's import table (data), never to its code — so a binary that
        /// checksums its own .text (anti-tamper) is captured without tripping the
        /// check. <paramref name="imports"/> is (slot VA, resolved target) pairs,
        /// e.g. from <see cref="ApiImportScanner.DiscoverImportSlots"/>.
        /// </summary>
        public static CaptureSession StartIat(
            int pid, IReadOnlyList<(ulong Slot, ulong Target)> imports, int maxFunctions, int bufferRecords,
            out int instrumented, out int skipped, out string? firstError)
        {
            var proc = TargetProcess.Attach(pid, forWrite: true);
            try
            {
                var memory = new RemoteMemory(proc);
                var code = new RemoteCodeMemory(proc, memory);
                int argCount = 4;
                int recordSize = CaptureStub.RecordSize(argCount);

                var buffer = CaptureBuffer.Create(code, bufferRecords, recordSize);
                var session = new CaptureSession(proc, code, buffer, argCount);

                instrumented = 0;
                skipped = 0;
                firstError = null;

                // No thread suspension: each hook is a single atomic, pointer-aligned
                // write, and the stub is fully built before the slot points at it.
                foreach (var (slotVa, target) in imports)
                {
                    if (instrumented >= maxFunctions) break;
                    try
                    {
                        ulong stub = memory.Allocate(StubBytesMax, executable: true);

                        // The stub records the call then jumps straight to the real
                        // function — an IAT hook has no stolen bytes, so destination
                        // == chain-back target == the real function.
                        byte[] stubBytes = CaptureStub.Build(proc.Is64Bit, stub, target,
                            buffer.ControlAddress, buffer.DataAddress, target, argCount, buffer.SlotCount);
                        if (stubBytes.Length > StubBytesMax) { skipped++; continue; }
                        code.Write(stub, stubBytes);
                        code.Flush(stub, stubBytes.Length);

                        // Point the slot at the stub (saving the original for teardown).
                        if (!IatHook.TryInstall(code, slotVa, stub, proc.Is64Bit,
                                out var hook, out string? skipReason))
                        {
                            skipped++;
                            firstError ??= skipReason;
                            continue;
                        }
                        session._iatHooks.Add(hook!);
                        instrumented++;
                    }
                    catch (Exception ex)
                    {
                        skipped++;
                        firstError ??= ex.Message;
                    }
                }

                return session;
            }
            catch
            {
                proc.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Diagnostic: bytes the in-target stubs have written so far (claimed
        /// slots × record size). If this grows, stubs ARE executing — the hooked
        /// functions are being called. If it stays 0, no hook ever fired.
        /// </summary>
        public int PeekWriteCursor()
            => unchecked((int)(_buffer.ReadClaimSeq(_code) * (uint)_buffer.RecordSize));

        /// <summary>
        /// Remove the entry detour from a single hooked function mid-capture,
        /// leaving every other hook in place. Used to stop instrumenting a
        /// "runaway" function — one called so often it floods the ring and forces
        /// record loss, drowning out the rest of the trace. The target's threads
        /// are frozen for the byte-restore (exactly as install/teardown does), so
        /// no thread is mid-instruction in the entry we rewrite. The stub and
        /// trampoline are deliberately NOT freed — a thread may still be executing
        /// inside them — so, like a normal stop, that memory is reclaimed only when
        /// the target exits. Returns true if a hook on <paramref name="functionAddress"/>
        /// was found and removed. Safe to call only from the same thread that polls
        /// (it is not synchronized against a concurrent <see cref="Poll"/>).
        /// </summary>
        public bool UnhookFunction(ulong functionAddress)
        {
            bool removed = false;

            int idx = _hooks.FindIndex(h => h.Target == functionAddress);
            if (idx >= 0)
            {
                using (new ThreadSuspender(_process.Pid))
                {
                    try { _hooks[idx].Remove(); } catch { /* best effort */ }
                }
                _hooks.RemoveAt(idx);
                removed = true;
            }

            // IAT: a runaway callee may be reached through several import slots; drop
            // every one (atomic pointer restores, no suspend needed).
            for (int i = _iatHooks.Count - 1; i >= 0; i--)
            {
                if (_iatHooks[i].Target != functionAddress) continue;
                try { _iatHooks[i].Remove(); } catch { /* best effort */ }
                _iatHooks.RemoveAt(i);
                removed = true;
            }
            return removed;
        }

        /// <summary>
        /// If <paramref name="address"/> lies inside a hooked function's footprint —
        /// its patched entry, its capture stub, or its trampoline — return that
        /// function's entry address; otherwise 0. Read-only; used by the startup crash
        /// watch to attribute a live fault to the hook whose generated code it faulted
        /// in. Call from the poll thread (it reads the same <c>_hooks</c> list
        /// <see cref="UnhookFunction"/> mutates).
        /// </summary>
        public ulong OwningHook(ulong address)
        {
            foreach (var h in _hooks)
                if (h.OwnsAddress(address, StubBytesMax)) return h.Target;
            return 0;
        }

        /// <summary>
        /// Read up to <paramref name="buffer"/>.Length bytes of the target at
        /// <paramref name="address"/>, returning the count read (0 on a bad pointer).
        /// Exposed so the crash watch can validate a stack word as a real return
        /// address (the bytes just before it should be a CALL) using this session's
        /// live handle, which is available even before the read-only UI session attaches.
        /// </summary>
        public int ReadTarget(ulong address, byte[] buffer) => _process.ReadMemory(address, buffer);

        /// <summary>Drain and decode records captured since the last poll.</summary>
        public List<CallRecord> Poll()
        {
            byte[] data = _buffer.DrainSince(_code, ref _readSeq, out int lost);
            if (lost > 0) RecordsLost += lost;
            if (data.Length < 8) return new List<CallRecord>();

            if (!_haveBase)
            {
                _tscBase = BitConverter.ToUInt64(data, 0);
                _haveBase = true;
            }

            // TSC frequency is unknown/variable; a nominal 1 GHz scale keeps the
            // timeline monotonic and roughly seconds-shaped. Exact timing later.
            var records = RingBufferReader.Decode(data, _tscBase, 1_000_000_000.0);
            EnrichDereferences(records);
            return records;
        }

        private const int DerefReadLength = 260;
        private const int MaxDerefDepth = 2; // follow up to this many pointer hops to find a string

        /// <summary>
        /// Host-side pointer following: for each captured argument that looks like
        /// a readable address, read a little memory from the target and, if it
        /// holds a string, attach a decoded dereference. If the immediate target
        /// isn't a string but its head looks like another pointer, follow that too
        /// (up to <see cref="MaxDerefDepth"/> hops) — this recovers strings behind a
        /// pointer-to-pointer (e.g. an LPWSTR* out-parameter) or sitting at the
        /// head of a small struct. Safe because every read is host-side via
        /// ReadProcessMemory, which simply returns nothing for a bad pointer — the
        /// target is never touched. A per-poll cache avoids re-reading the same
        /// argument pointer (string pointers recur a lot).
        /// </summary>
        private void EnrichDereferences(List<CallRecord> records)
        {
            int budget = 16000; // bound the ReadProcessMemory calls per poll
            var cache = new Dictionary<ulong, Dereference?>();
            byte[] buf = new byte[DerefReadLength];

            foreach (var rec in records)
            {
                List<Dereference>? derefs = null;

                // (a) the integer args the stub captured directly (x64: RCX/RDX/R8/R9
                // and the leading stack spill; x86: the leading stack slots).
                ulong[] args = rec.IntegerArgs;
                for (int i = 0; i < args.Length; i++)
                    TryDeref(args[i], i, ref derefs, cache, buf, ref budget);

                // (b) every further positional argument read from the captured stack
                // snapshot — NO fixed arg-count cap, so a string passed at arg11, arg20,
                // … still decodes. snapshot[0] is the return address; argument i lives at
                // snapshot[i+1] for both x86 (every argument on the stack) and x64 (the
                // 5th argument onward sits just past the 32-byte shadow space). What
                // bounds this isn't an arbitrary arity but the string's own NUL
                // terminator: a word is only surfaced when it points at a printable,
                // NUL-terminated run (Classify), which rejects return addresses and the
                // non-string words a frame holds. The reach is the snapshot depth
                // (CaptureStub.StackSlots words ⇒ up to that many args).
                ulong[] snap = rec.StackSnapshot;
                for (int i = Math.Max(args.Length, 4); i + 1 < snap.Length; i++)
                    TryDeref(snap[i + 1], i, ref derefs, cache, buf, ref budget);

                if (derefs != null) rec.Dereferences = derefs.ToArray();
            }
        }

        // Dereference one candidate argument pointer and, if it resolves to a string,
        // append it as argument <argIndex>. Shared by the captured-args and
        // stack-snapshot passes; the per-poll cache makes a recurring pointer cheap.
        private void TryDeref(ulong p, int argIndex, ref List<Dereference>? derefs,
            Dictionary<ulong, Dereference?> cache, byte[] buf, ref int budget)
        {
            if (!LooksLikePointer(p)) return;

            if (!cache.TryGetValue(p, out var proto))
            {
                proto = ResolvePointer(p, MaxDerefDepth, buf, ref budget);
                cache[p] = proto;
            }
            if (proto == null) return;

            (derefs ??= new List<Dereference>()).Add(new Dereference
            {
                ArgumentIndex = argIndex,
                Kind = proto.Kind,
                Pointer = proto.Pointer,
                Data = proto.Data,
            });
        }

        // Follow up to <depth> pointer hops from <ptr> looking for a string. Returns
        // a prototype dereference (ArgumentIndex unset) for the first string found,
        // whose Pointer is the address the string actually lives at (so its Data is
        // self-consistent), else null. Bounded by <depth> and the shared read budget
        // to avoid runaway and to keep struct-head false positives rare (Classify
        // already requires a printable, terminated run).
        private Dereference? ResolvePointer(ulong ptr, int depth, byte[] buf, ref int budget)
        {
            if (budget <= 0 || depth < 0 || !LooksLikePointer(ptr)) return null;
            budget--;
            int n = _process.ReadMemory(ptr, buf);
            if (n <= 0) return null;

            var str = Classify(buf, n, ptr);
            if (str != null) return str;

            if (depth > 0)
            {
                // Read the head as a pointer of the target's width and follow it.
                ulong inner = _process.Is64Bit
                    ? (n >= 8 ? BitConverter.ToUInt64(buf, 0) : 0)
                    : (n >= 4 ? BitConverter.ToUInt32(buf, 0) : 0);
                if (inner != ptr && LooksLikePointer(inner))
                    return ResolvePointer(inner, depth - 1, buf, ref budget);
            }
            return null;
        }

        private bool LooksLikePointer(ulong v) => v >= 0x10000 && v < _process.MaxAddress;

        // Returns a prototype dereference (ArgumentIndex unset) if the bytes look
        // like an ANSI or UTF-16 string; otherwise null.
        private static Dereference? Classify(byte[] b, int n, ulong ptr)
        {
            // UTF-16: alternating printable / zero bytes.
            if (n >= 4 && b[1] == 0 && b[3] == 0 && IsPrint(b[0]) && IsPrint(b[2]))
            {
                int len = 0;
                while (len + 1 < n && !(b[len] == 0 && b[len + 1] == 0)) len += 2;
                if (len >= 4)
                {
                    var data = new byte[len];
                    Array.Copy(b, data, len);
                    return new Dereference { Kind = DereferenceKind.WideString, Pointer = ptr, Data = data };
                }
            }
            // ANSI: a run of printable / whitespace bytes ending in a null. The run
            // starts on a real printable char but may contain tab/newline/CR, so a
            // message or format string ("…%s\n") isn't truncated at its first newline.
            if (IsPrint(b[0]))
            {
                int len = 0;
                while (len < n && b[len] != 0 && IsStrChar(b[len])) len++;
                if (len >= 3 && len < n && b[len] == 0)
                {
                    var data = new byte[len];
                    Array.Copy(b, data, len);
                    return new Dereference { Kind = DereferenceKind.AnsiString, Pointer = ptr, Data = data };
                }
            }
            return null;
        }

        private static bool IsPrint(byte c) => c >= 0x20 && c <= 0x7E;

        // Characters allowed inside a string run: printable ASCII plus the common
        // whitespace controls (tab, LF, CR) that legitimately appear in messages and
        // format strings — excluding them truncated such strings at the first newline.
        private static bool IsStrChar(byte c) => IsPrint(c) || c == 0x09 || c == 0x0A || c == 0x0D;

        public void Dispose()
        {
            // Inline hooks rewrite .text, so restore them with the target frozen (no
            // thread mid-instruction in a site we're rewriting). Skip the freeze
            // entirely for an IAT-only session.
            if (_hooks.Count > 0)
            {
                using (new ThreadSuspender(_process.Pid))
                {
                    foreach (var hook in _hooks)
                    {
                        try { hook.Remove(); } catch { /* best effort */ }
                    }
                }
            }
            _hooks.Clear();

            // IAT hooks are atomic pointer restores — no suspend needed. A thread may
            // still be inside a stub, but the stub chains to the real function, so
            // restoring the slot only affects future calls.
            foreach (var h in _iatHooks)
            {
                try { h.Remove(); } catch { /* best effort */ }
            }
            _iatHooks.Clear();

            // Deliberately DO NOT free the stubs/trampolines/buffer. A thread may
            // still be executing inside a stub or trampoline, or be poised to
            // return into one; freeing would crash the target. These regions are
            // reclaimed when the target exits. (Bounded leak per capture session.)
            _process.Dispose();
        }
    }
}
