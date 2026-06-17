using System;
using System.Collections.Generic;
using Cda.Core.Model;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Exact x64 stack unwinding using the target's <c>.pdata</c> / unwind
    /// information, walked over a captured per-call stack snapshot.
    ///
    /// The capture stub records a fixed window of stack words from the callee's
    /// entry SP upward. The word-scan heuristic in the host guesses which of those
    /// words are caller return addresses; this class instead does it precisely: for
    /// each frame it looks up the function's <c>RUNTIME_FUNCTION</c> in the owning
    /// module's <c>.pdata</c>, sums the prologue's stack allocations from the
    /// <c>UNWIND_INFO</c> codes (following chained info), and reads the return
    /// address from the exact slot. Because it understands each frame's real size,
    /// it can step <i>through</i> runtime / CRT frames to reach the program's own
    /// callers that a word scan would miss or mis-identify.
    ///
    /// Entirely host-side and read-only: <c>.pdata</c> / <c>UNWIND_INFO</c> come
    /// from the module images (stable, read-only) via ReadProcessMemory, and the
    /// stack itself is read only from the captured snapshot — the target is never
    /// touched and nothing can crash it. It is conservative by design: anything it
    /// can't unwind exactly (a function with no unwind info, an established frame
    /// pointer it would need a live register for, a machine-frame, or a slot beyond
    /// the snapshot window) simply stops the walk, so the caller can fall back to
    /// the heuristic. x64 only.
    /// </summary>
    public sealed class StackUnwinder
    {
        private readonly TargetProcess _process;
        private readonly ModuleMap _modules;

        // Per-module parsed .pdata (function table). null = module has no usable
        // exception data (and we never retry it).
        private readonly Dictionary<ulong, ModulePdata?> _pdata = new();

        // Per-call stack image (set at the start of each Unwind).
        private ulong _entryRsp;
        private ulong[] _snapshot = Array.Empty<ulong>();

        // Per-function frame-size cache sentinels (see ModulePdata.FrameAdd).
        private const long FrameUncomputed = long.MinValue;
        private const long FrameCannot = -1;

        public StackUnwinder(TargetProcess process, ModuleMap modules)
        {
            _process = process;
            _modules = modules;
        }

        /// <summary>
        /// Walk the call stack from a captured entry, returning caller return
        /// addresses innermost-first. Uses the snapshot as the stack image and the
        /// target's unwind info for frame sizes. <paramref name="validate"/>, if
        /// given, must accept each return address (e.g. "looks preceded by a CALL");
        /// the walk stops at the first frame that fails it, so a confused unwind
        /// self-limits instead of emitting garbage.
        /// </summary>
        public List<ulong> Unwind(ulong entryRsp, ulong[] snapshot,
                                  Func<ulong, bool>? validate = null, int maxFrames = 64)
        {
            var ras = new List<ulong>();
            if (snapshot == null || snapshot.Length == 0) return ras;

            _entryRsp = entryRsp;
            _snapshot = snapshot;

            // Frame 0: the callee was just entered (snapshot taken before its
            // prologue ran), so its return address sits at [entryRsp].
            if (!TryReadStack(entryRsp, out ulong ra0)) return ras;
            if (ra0 == 0 || _modules.Resolve(ra0) == null) return ras;
            if (validate != null && !validate(ra0)) return ras;
            ras.Add(ra0);

            ulong rip = ra0;
            ulong rsp = entryRsp + 8;
            for (int frame = 1; frame < maxFrames; frame++)
            {
                var mod = _modules.Resolve(rip);
                if (mod == null) break;
                if (!TryFrameAdvance(mod.BaseAddress, rip, out ulong rspAdd)) break;

                ulong raSlot = rsp + rspAdd;
                if (!TryReadStack(raSlot, out ulong ra)) break;          // beyond the snapshot window
                if (ra == 0 || _modules.Resolve(ra) == null) break;      // not a code address — desync
                if (validate != null && !validate(ra)) break;

                ras.Add(ra);
                rip = ra;
                rsp = raSlot + 8;
            }
            return ras;
        }

        // Read a stack word from the captured snapshot by absolute address.
        private bool TryReadStack(ulong addr, out ulong value)
        {
            value = 0;
            if (addr < _entryRsp) return false;
            ulong off = addr - _entryRsp;
            if ((off & 7) != 0) return false;
            ulong idx = off >> 3;
            if (idx >= (ulong)_snapshot.Length) return false;
            value = _snapshot[idx];
            return true;
        }

        // Total bytes the prologue of the function containing <rip> allocates above
        // the current RSP, i.e. the offset from RSP to the saved return address.
        // false = can't unwind exactly (no info / frame-pointer / machine-frame /
        // unknown op) — caller should stop.
        private bool TryFrameAdvance(ulong moduleBase, ulong rip, out ulong rspAdd)
        {
            rspAdd = 0;
            var pd = GetPdata(moduleBase);
            if (pd == null) return false;

            uint rva = (uint)(rip - moduleBase);
            int idx = FindFunction(pd, rva);
            if (idx < 0) return false;

            // A function's prologue frame size is constant, and the same functions
            // recur constantly across a trace, so cache it per function. This is
            // what keeps the unwinder from re-reading UNWIND_INFO out of the target
            // on every folded record — the fold runs on the UI thread during
            // capture, so uncached cross-process reads there stall the window.
            long cached = pd.FrameAdd[idx];
            if (cached >= 0) { rspAdd = (ulong)cached; return true; }
            if (cached == FrameCannot) return false;

            uint unwindRva = pd.Unwind[idx];
            ulong total = 0;
            for (int chain = 0; chain < 16; chain++)
            {
                if (!ReadUnwind(moduleBase, unwindRva, out ulong add, out bool chained, out uint next))
                {
                    pd.FrameAdd[idx] = FrameCannot;
                    return false;
                }
                total += add;
                if (!chained) { pd.FrameAdd[idx] = (long)total; rspAdd = total; return true; }
                unwindRva = next;
            }
            pd.FrameAdd[idx] = FrameCannot; // chain too deep — give up (and remember)
            return false;
        }

        // Parse one UNWIND_INFO: sum its stack-allocating codes into <add>, and
        // report whether it chains to another (and where). false on any op we can't
        // unwind exactly.
        private bool ReadUnwind(ulong moduleBase, uint unwindRva,
                                out ulong add, out bool chained, out uint nextUnwindRva)
        {
            add = 0; chained = false; nextUnwindRva = 0;

            byte[] head = new byte[4];
            if (_process.ReadMemory(moduleBase + unwindRva, head) < 4) return false;
            int verFlags = head[0];
            int version = verFlags & 0x7;
            int flags = (verFlags >> 3) & 0x1F;
            int count = head[2];
            if (version != 1 && version != 2) return false;

            int codeBytes = count * 2;
            byte[] codes = codeBytes > 0 ? new byte[codeBytes] : Array.Empty<byte>();
            if (codeBytes > 0 && _process.ReadMemory(moduleBase + unwindRva + 4, codes) < codeBytes) return false;

            int i = 0;
            while (i < count)
            {
                int op = codes[i * 2 + 1] & 0xF;
                int opInfo = (codes[i * 2 + 1] >> 4) & 0xF;
                switch (op)
                {
                    case 0: // UWOP_PUSH_NONVOL
                        add += 8; i += 1; break;
                    case 1: // UWOP_ALLOC_LARGE
                        if (opInfo == 0)
                        {
                            if (i + 1 >= count) return false;
                            uint u16 = (uint)(codes[(i + 1) * 2] | (codes[(i + 1) * 2 + 1] << 8));
                            add += (ulong)u16 * 8; i += 2;
                        }
                        else
                        {
                            if (i + 2 >= count) return false;
                            uint u32 = (uint)(codes[(i + 1) * 2]
                                            | (codes[(i + 1) * 2 + 1] << 8)
                                            | (codes[(i + 2) * 2] << 16)
                                            | (codes[(i + 2) * 2 + 1] << 24));
                            add += u32; i += 3;
                        }
                        break;
                    case 2: // UWOP_ALLOC_SMALL
                        add += (ulong)(opInfo * 8 + 8); i += 1; break;
                    case 3: // UWOP_SET_FPREG — would need the live frame register
                        return false;
                    case 4: i += 2; break; // UWOP_SAVE_NONVOL (no SP change)
                    case 5: i += 3; break; // UWOP_SAVE_NONVOL_FAR
                    case 8: i += 2; break; // UWOP_SAVE_XMM128
                    case 9: i += 3; break; // UWOP_SAVE_XMM128_FAR
                    case 10: // UWOP_PUSH_MACHFRAME — trap frame, not a normal call
                        return false;
                    default: // incl. version-2 UWOP_EPILOG(6)/UWOP_SPARE(7)
                        return false;
                }
            }

            if ((flags & 0x4) != 0) // UNW_FLAG_CHAININFO
            {
                int aligned = (count + 1) & ~1;       // codes padded to an even count
                uint chainRva = unwindRva + 4 + (uint)(aligned * 2);
                byte[] rf = new byte[12];             // chained RUNTIME_FUNCTION
                if (_process.ReadMemory(moduleBase + chainRva, rf) < 12) return false;
                nextUnwindRva = BitConverter.ToUInt32(rf, 8);
                chained = true;
            }
            return true;
        }

        // Binary-search a module's function table for the entry covering <rva>.
        private static int FindFunction(ModulePdata pd, uint rva)
        {
            int lo = 0, hi = pd.Begin.Length - 1, res = -1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >> 1;
                if (pd.Begin[mid] <= rva) { res = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            if (res < 0 || rva >= pd.End[res]) return -1; // in a gap between functions
            return res;
        }

        private ModulePdata? GetPdata(ulong moduleBase)
        {
            if (_pdata.TryGetValue(moduleBase, out var cached)) return cached;
            var built = BuildPdata(moduleBase);
            _pdata[moduleBase] = built;
            return built;
        }

        // Read the module's PE headers from target memory, locate the exception
        // directory (.pdata), and parse its RUNTIME_FUNCTION array. PE32+ only.
        private ModulePdata? BuildPdata(ulong moduleBase)
        {
            byte[] hdr = new byte[0x400];
            int n = _process.ReadMemory(moduleBase, hdr);
            if (n < 0x40) return null;
            if (hdr[0] != 0x4D || hdr[1] != 0x5A) return null;           // 'MZ'

            int e = BitConverter.ToInt32(hdr, 0x3C);                     // e_lfanew
            if (e <= 0 || e + 24 + 144 > n) return null;
            if (BitConverter.ToUInt32(hdr, e) != 0x00004550) return null; // 'PE\0\0'
            ushort magic = BitConverter.ToUInt16(hdr, e + 24);
            if (magic != 0x20B) return null;                              // not PE32+ (x64)

            uint rva = BitConverter.ToUInt32(hdr, e + 24 + 136);          // Exception dir RVA
            uint size = BitConverter.ToUInt32(hdr, e + 24 + 140);         // Exception dir size
            if (rva == 0 || size < 12) return null;

            int count = (int)(size / 12);
            if (count <= 0 || count > 4_000_000) return null;             // sanity bound

            byte[] pdata = new byte[count * 12];
            int got = _process.ReadMemory(moduleBase + rva, pdata);
            int have = got / 12;
            if (have <= 0) return null;

            var begin = new uint[have];
            var end = new uint[have];
            var unwind = new uint[have];
            for (int i = 0; i < have; i++)
            {
                begin[i] = BitConverter.ToUInt32(pdata, i * 12);
                end[i] = BitConverter.ToUInt32(pdata, i * 12 + 4);
                unwind[i] = BitConverter.ToUInt32(pdata, i * 12 + 8);
            }
            var frameAdd = new long[have];
            for (int i = 0; i < have; i++) frameAdd[i] = FrameUncomputed;
            return new ModulePdata { Begin = begin, End = end, Unwind = unwind, FrameAdd = frameAdd };
        }

        // A module's parsed function table (.pdata), sorted by Begin RVA.
        private sealed class ModulePdata
        {
            public uint[] Begin = Array.Empty<uint>();
            public uint[] End = Array.Empty<uint>();
            public uint[] Unwind = Array.Empty<uint>();
            // Per-function cached prologue frame size: FrameUncomputed = not yet
            // computed, FrameCannot = can't unwind exactly, else the rsp delta.
            public long[] FrameAdd = Array.Empty<long>();
        }
    }
}
