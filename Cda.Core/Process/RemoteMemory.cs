using System;
using System.Runtime.InteropServices;

namespace Cda.Core.Process
{
    /// <summary>
    /// Allocates and protects memory inside the target process — the buffers
    /// that instrumentation trampolines and the record ring buffer live in.
    /// This is the modern, cross-bitness replacement for the legacy in-target
    /// allocation done through <c>oMemoryFunctions</c>.
    ///
    /// Each allocation is tracked so <see cref="Dispose"/> frees them all when a
    /// session detaches. <see cref="AllocateNear"/> additionally places executable
    /// blocks within the +/-2GB rel32 reach of a hooked x64 module (found via a
    /// VirtualQueryEx free-region scan), so an entry detour is a 5-byte E9 and the
    /// stolen prologue's RIP-relative operands relocate in range; it sub-allocates
    /// stubs and trampolines from those blocks.
    /// </summary>
    public sealed class RemoteMemory : IDisposable
    {
        private readonly TargetProcess _process;
        private readonly System.Collections.Generic.List<(IntPtr addr, IntPtr size)> _allocs = new();

        public RemoteMemory(TargetProcess process) => _process = process;

        /// <summary>Commit a block in the target. <paramref name="executable"/> picks RWX vs RW.</summary>
        public ulong Allocate(int size, bool executable)
        {
            uint protect = executable ? NativeMethods.PAGE_EXECUTE_READWRITE : NativeMethods.PAGE_READWRITE;
            IntPtr p = NativeMethods.VirtualAllocEx(
                _process.Handle, IntPtr.Zero, (IntPtr)size,
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, protect);
            if (p == IntPtr.Zero)
                throw new InvalidOperationException(
                    $"VirtualAllocEx failed (error {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}).");
            _allocs.Add((p, (IntPtr)size));
            return (ulong)p.ToInt64();
        }

        // --- near (rel32-reachable) allocation -------------------------------
        //
        // A far VirtualAllocEx (NULL base) lands wherever the OS chooses — routinely
        // >2GB from an image based at 0x140000000. That forces every x64 entry
        // detour to the 14-byte FF25 indirect form (stealing 14 prologue bytes
        // instead of 5, relocating 3-5 instructions and reaching far deeper into the
        // function) and makes stolen RIP-relative operands unrelocatable (">2GB" →
        // the site is skipped). Placing the stub + trampoline WITHIN +/-2GB of the
        // target instead lets the detour be a clean 5-byte E9 (steal 5), keeps
        // relocations in rel32 range, and cuts the skip count — the difference
        // between corrupting some programs and tracing them cleanly.
        //
        // Memory is carved from 64KB blocks found near the anchor by a VirtualQueryEx
        // free-region scan and bump-allocated. A block placed for one function serves
        // every other function in the same module (a module is far smaller than the
        // 2GB window). If no near block can be placed we fall back to a far allocation
        // — the hook then behaves exactly as before (14-byte detour, or skipped).

        private sealed class NearBlock { public ulong Base, Next, End; }
        private readonly System.Collections.Generic.List<NearBlock> _nearBlocks = new();

        private const ulong NearGranularity = 0x10000;  // VirtualAllocEx reservation granularity (64KB)
        private const int NearBlockBytes = 0x10000;     // one reservation backs many stubs/trampolines
        private const ulong NearReach = 0x70000000;     // ~1.75GB: margin under the 2GB rel32 limit
        private static readonly int MbiSize =
            Marshal.SizeOf<NativeMethods.MEMORY_BASIC_INFORMATION>();

        /// <summary>
        /// Allocate <paramref name="size"/> bytes of RWX memory within +/-2GB of
        /// <paramref name="anchor"/> when possible (so an x64 E9 rel32 from the
        /// anchor reaches it), else fall back to a normal far allocation. The result
        /// is 16-byte aligned (code). Blocks are tracked like every other allocation.
        /// </summary>
        public ulong AllocateNear(int size, ulong anchor)
        {
            int need = (size + 15) & ~15;

            // Reuse a near block that still has room AND is in rel32 range of this
            // anchor (the common case once one block is placed for the module).
            foreach (var b in _nearBlocks)
            {
                if (b.Next + (ulong)need > b.End) continue;
                if (!InReach(anchor, b.Next) || !InReach(anchor, b.Next + (ulong)need - 1)) continue;
                ulong at = b.Next;
                b.Next += (ulong)need;
                return at;
            }

            // Place a new block near the anchor and sub-allocate from it.
            int blockBytes = Math.Max(need, NearBlockBytes);
            ulong slot = FindFreeNear(anchor, (ulong)blockBytes);
            if (slot != 0)
            {
                IntPtr p = NativeMethods.VirtualAllocEx(_process.Handle, (IntPtr)unchecked((long)slot),
                    (IntPtr)blockBytes, NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE,
                    NativeMethods.PAGE_EXECUTE_READWRITE);
                if (p != IntPtr.Zero)
                {
                    ulong basis = (ulong)p.ToInt64();
                    _allocs.Add((p, (IntPtr)blockBytes));
                    _nearBlocks.Add(new NearBlock
                    {
                        Base = basis,
                        Next = basis + (ulong)need,
                        End = basis + (ulong)blockBytes,
                    });
                    return basis;
                }
            }

            // No near slot (or the explicit-base reservation failed): fall back to a
            // far allocation. The caller still succeeds — the x64 detour just uses
            // the 14-byte indirect form, as it did before this path existed.
            return Allocate(size, executable: true);
        }

        private static bool InReach(ulong anchor, ulong addr)
        {
            ulong d = anchor > addr ? anchor - addr : addr - anchor;
            return d <= NearReach;
        }

        // Find a MEM_FREE, allocation-granular slot of <paramref name="size"/> bytes
        // within +/-NearReach of <paramref name="anchor"/>. Probes just above the
        // anchor first (so the block sits right past the module, reachable by every
        // function in it), then just below. Returns 0 if nothing in range fits.
        private ulong FindFreeNear(ulong anchor, ulong size)
        {
            ulong hi = anchor > ulong.MaxValue - NearReach ? ulong.MaxValue : anchor + NearReach;
            ulong lo = anchor > NearReach ? anchor - NearReach : NearGranularity;

            ulong above = ScanUp(RoundUpGran(anchor), hi, size, preferHighest: false);
            if (above != 0) return above;
            return ScanUp(RoundUpGran(lo), RoundUpGran(anchor), size, preferHighest: true);
        }

        // Walk [start, limit) upward over VM regions. In each MEM_FREE region take
        // the lowest granular slot that fits (preferHighest=false → return the first,
        // closest above the anchor) or the highest (preferHighest=true → keep the
        // last, closest below the anchor).
        private ulong ScanUp(ulong start, ulong limit, ulong size, bool preferHighest)
        {
            if (start >= limit) return 0;
            ulong addr = start;
            ulong best = 0;
            int guard = 0;
            while (addr < limit && guard++ < 200000)
            {
                if (NativeMethods.VirtualQueryEx(_process.Handle, (IntPtr)unchecked((long)addr),
                        out var mbi, (IntPtr)MbiSize) == IntPtr.Zero)
                    break;
                ulong rBase = (ulong)mbi.BaseAddress.ToInt64();
                ulong rSize = (ulong)mbi.RegionSize.ToInt64();
                if (rSize == 0) break;
                ulong rEnd = rBase + rSize;

                if (mbi.State == NativeMethods.MEM_FREE)
                {
                    ulong winLo = Math.Max(rBase, start);
                    ulong winHi = Math.Min(rEnd, limit);
                    if (winHi > size && winHi - size >= winLo)
                    {
                        ulong fit = preferHighest ? FloorGran(winHi - size) : RoundUpGran(winLo);
                        if (fit >= winLo && fit + size <= winHi)
                        {
                            if (!preferHighest) return fit;
                            best = fit; // remember the highest fit (closest below the anchor)
                        }
                    }
                }
                ulong next = rEnd;
                if (next <= addr) next = addr + NearGranularity; // guarantee forward progress
                addr = next;
            }
            return best;
        }

        private static ulong RoundUpGran(ulong v) => (v + (NearGranularity - 1)) & ~(NearGranularity - 1);
        private static ulong FloorGran(ulong v) => v & ~(NearGranularity - 1);

        public void Write(ulong address, ReadOnlySpan<byte> data)
        {
            int n = _process.WriteMemory(address, data);
            if (n != data.Length)
                throw new InvalidOperationException(
                    $"WriteProcessMemory wrote {n}/{data.Length} bytes at 0x{address:X} " +
                    $"(error {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}).");
        }

        public uint Protect(ulong address, int size, uint protect)
        {
            if (!NativeMethods.VirtualProtectEx(_process.Handle, (IntPtr)unchecked((long)address),
                    (IntPtr)size, protect, out uint old))
                throw new InvalidOperationException(
                    $"VirtualProtectEx failed at 0x{address:X} " +
                    $"(error {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}).");
            return old;
        }

        /// <summary>Flush the CPU instruction cache after writing code (mandatory on patches).</summary>
        public void FlushCode(ulong address, int size) =>
            NativeMethods.FlushInstructionCache(_process.Handle, (IntPtr)unchecked((long)address), (IntPtr)size);

        public void Dispose()
        {
            foreach (var (addr, _) in _allocs)
                NativeMethods.VirtualFreeEx(_process.Handle, addr, IntPtr.Zero, NativeMethods.MEM_RELEASE);
            _allocs.Clear();
        }
    }
}
