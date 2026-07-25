using System;
using System.Buffers.Binary;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// An Import-Address-Table hook: it redirects an imported function by
    /// overwriting its bound IAT slot (a pointer in the module's import table)
    /// with the address of a capture stub, instead of patching the function's
    /// code. The program calls imports indirectly (<c>call [IAT slot]</c>), so
    /// swapping the slot pointer reroutes every such call through the stub, which
    /// records it and then jumps straight to the real function.
    ///
    /// Why this exists alongside <see cref="InlineHook"/>: an inline hook writes
    /// into the target's <c>.text</c>, which a binary that checksums its own code
    /// (anti-tamper) detects, killing itself. An IAT slot lives in the import data
    /// (<c>.rdata</c>/<c>.idata</c>) and is written by the loader at every launch
    /// (ASLR/binding), so it isn't meaningfully checksummed — this captures the
    /// program's calls OUT to the OS without modifying a single byte of its code.
    ///
    /// The caller suspends the process around installation/removal because
    /// cross-process writes do not guarantee an atomic pointer exchange. The stub
    /// is fully built before the slot is redirected. On <see cref="Remove"/> the
    /// original pointer is written back only if the slot still points at this
    /// hook's stub; the stub memory is intentionally retained by the session
    /// because a thread may still be inside it.
    /// </summary>
    public sealed class IatHook
    {
        /// <summary>VA of the IAT slot that was overwritten.</summary>
        public ulong SlotAddress { get; }

        /// <summary>The real function the slot pointed at (restored on Remove); also
        /// the recorded callee, so the runaway-unhook can match on it.</summary>
        public ulong Target { get; }

        public ulong Stub { get; }

        private readonly ICodeMemory _mem;
        private readonly int _ptr;
        private bool _removed;
        internal bool NeedsCleanup => !_removed;

        private IatHook(ICodeMemory mem, ulong slot, ulong target, ulong stub, int ptr)
        {
            _mem = mem;
            SlotAddress = slot;
            Target = target;
            Stub = stub;
            _ptr = ptr;
        }

        /// <summary>
        /// Read the slot's current (real) pointer, then point it at
        /// <paramref name="stub"/>. Returns false (with a reason) for the routine
        /// cases a slot can't be hooked — unreadable, or unbound (null) — so a broad
        /// sweep reports them rather than throwing.
        /// </summary>
        public static bool TryInstall(ICodeMemory mem, ulong slot, ulong stub, bool is64,
            out IatHook? hook, out string? skipReason)
        {
            hook = null;
            skipReason = null;
            int ptr = is64 ? 8 : 4;

            Span<byte> buf = stackalloc byte[8];
            if (mem.Read(slot, buf.Slice(0, ptr)) < ptr)
            {
                skipReason = "Couldn't read the IAT slot.";
                return false;
            }
            ulong original = ptr == 8
                ? BinaryPrimitives.ReadUInt64LittleEndian(buf)
                : BinaryPrimitives.ReadUInt32LittleEndian(buf);
            if (original == 0)
            {
                skipReason = "IAT slot is null (unbound import).";
                return false;
            }
            if (original == stub) { skipReason = "IAT slot already points at our stub."; return false; }

            hook = new IatHook(mem, slot, original, stub, ptr);
            try
            {
                WriteSlot(mem, slot, stub, ptr);
            }
            catch
            {
                // The candidate is exposed before the target mutation. A successful
                // rollback marks it removed; a failed rollback leaves NeedsCleanup
                // true so CaptureSession can retain and retry it at teardown.
                try { hook.Remove(); } catch { }
                throw;
            }
            return true;
        }

        /// <summary>Restore the original (real) function pointer into the slot.</summary>
        public void Remove()
        {
            if (_removed) return;
            ulong current = ReadSlot(_mem, SlotAddress, _ptr);
            if (current == Target)
            {
                _removed = true;
                return;
            }
            if (current != Stub)
                throw new InvalidOperationException(
                    $"IAT slot 0x{SlotAddress:X} no longer belongs to this hook " +
                    $"(expected stub 0x{Stub:X}, found 0x{current:X}); refusing to overwrite it.");
            WriteSlot(_mem, SlotAddress, Target, _ptr);
            _removed = true;
        }

        private static ulong ReadSlot(ICodeMemory mem, ulong slot, int ptr)
        {
            Span<byte> b = stackalloc byte[8];
            if (mem.Read(slot, b.Slice(0, ptr)) != ptr)
                throw new InvalidOperationException($"Couldn't read IAT slot 0x{slot:X}.");
            return ptr == 8
                ? BinaryPrimitives.ReadUInt64LittleEndian(b)
                : BinaryPrimitives.ReadUInt32LittleEndian(b);
        }

        // Write a pointer-sized value into the slot, flipping the page to writable
        // for the write if the loader left it read-only and restoring its
        // protection afterward. The owning session suspends the target around it.
        private static void WriteSlot(ICodeMemory mem, ulong slot, ulong value, int ptr)
        {
            uint old = mem.Protect(slot, ptr, NativeMethods.PAGE_READWRITE);
            Span<byte> b = stackalloc byte[8];
            if (ptr == 8) BinaryPrimitives.WriteUInt64LittleEndian(b, value);
            else BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)value);
            try
            {
                mem.Write(slot, b.Slice(0, ptr));
            }
            finally
            {
                mem.Protect(slot, ptr, old);
            }
        }
    }
}
