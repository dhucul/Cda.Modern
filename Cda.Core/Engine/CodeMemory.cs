using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Read/write/allocate/execute-protect over some address space, used by the
    /// hook engine. The same hook codegen runs against this process (for the
    /// in-process self-test) or a remote target (real instrumentation), so the
    /// dangerous code generation can be validated in isolation from cross-process
    /// injection.
    /// </summary>
    public interface ICodeMemory
    {
        bool Is64Bit { get; }
        ulong Allocate(int size, bool executable);
        /// <summary>
        /// Allocate executable memory within +/-2GB of <paramref name="near"/> when
        /// possible (so an x64 E9 rel32 reaches it), falling back to a far allocation
        /// otherwise. Used for stubs and trampolines so the entry detour stays a
        /// 5-byte jump and stolen RIP-relative operands relocate in range.
        /// </summary>
        ulong AllocateNear(int size, ulong near);
        /// <summary>Release or rewind a failed near allocation when possible.</summary>
        bool ReleaseNear(ulong address, int size);
        int Read(ulong address, Span<byte> buffer);
        void Write(ulong address, ReadOnlySpan<byte> data);
        uint Protect(ulong address, int size, uint protect);
        void Flush(ulong address, int size);
    }

    /// <summary>Operates on the current process — used only by the self-test.</summary>
    public sealed class LocalCodeMemory : ICodeMemory, IDisposable
    {
        private readonly System.Collections.Generic.List<IntPtr> _allocations = new();
        private bool _disposed;

        public bool Is64Bit => IntPtr.Size == 8;

        public ulong Allocate(int size, bool executable)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            uint protect = executable ? NativeMethods.PAGE_EXECUTE_READWRITE : NativeMethods.PAGE_READWRITE;
            IntPtr p = NativeMethods.VirtualAlloc(IntPtr.Zero, (IntPtr)size,
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, protect);
            if (p == IntPtr.Zero)
                throw new InvalidOperationException($"VirtualAlloc failed ({Marshal.GetLastWin32Error()}).");
            _allocations.Add(p);
            return NativeMethods.ToUInt64(p);
        }

        // The in-process self-test doesn't run the free-region scan; a far
        // allocation here exercises the same codegen and keeps the self-test
        // behaviour identical to before near-allocation existed.
        public ulong AllocateNear(int size, ulong near) => Allocate(size, executable: true);

        public bool ReleaseNear(ulong address, int size)
        {
            IntPtr p = NativeMethods.ToIntPtr(address);
            int index = _allocations.IndexOf(p);
            if (index < 0) return false;
            if (!NativeMethods.VirtualFree(p, IntPtr.Zero, NativeMethods.MEM_RELEASE)) return false;
            _allocations.RemoveAt(index);
            return true;
        }

        public int Read(ulong address, Span<byte> buffer)
        {
            byte[] tmp = new byte[buffer.Length];
            Marshal.Copy(NativeMethods.ToIntPtr(address), tmp, 0, tmp.Length);
            tmp.CopyTo(buffer);
            return buffer.Length;
        }

        public void Write(ulong address, ReadOnlySpan<byte> data)
        {
            byte[] tmp = data.ToArray();
            Marshal.Copy(tmp, 0, NativeMethods.ToIntPtr(address), tmp.Length);
        }

        public uint Protect(ulong address, int size, uint protect)
        {
            if (!NativeMethods.VirtualProtect(NativeMethods.ToIntPtr(address), (IntPtr)size, protect, out uint old))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    $"VirtualProtect failed at 0x{address:X}.");
            return old;
        }

        public void Flush(ulong address, int size)
        {
            if (!NativeMethods.FlushInstructionCache(NativeMethods.GetCurrentProcess(),
                    NativeMethods.ToIntPtr(address), (IntPtr)size))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    $"FlushInstructionCache failed at 0x{address:X}.");
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            foreach (IntPtr allocation in _allocations)
                NativeMethods.VirtualFree(allocation, IntPtr.Zero, NativeMethods.MEM_RELEASE);
            _allocations.Clear();
        }
    }

    /// <summary>Operates on a remote target via <see cref="RemoteMemory"/>.</summary>
    public sealed class RemoteCodeMemory : ICodeMemory
    {
        private readonly TargetProcess _process;
        private readonly RemoteMemory _memory;

        public RemoteCodeMemory(TargetProcess process, RemoteMemory memory)
        {
            _process = process;
            _memory = memory;
        }

        public bool Is64Bit => _process.Is64Bit;
        public ulong Allocate(int size, bool executable) => _memory.Allocate(size, executable);
        public ulong AllocateNear(int size, ulong near) => _memory.AllocateNear(size, near);
        public bool ReleaseNear(ulong address, int size) => _memory.ReleaseNear(address, size);
        public int Read(ulong address, Span<byte> buffer) => _process.ReadMemory(address, buffer);
        public void Write(ulong address, ReadOnlySpan<byte> data) => _memory.Write(address, data);
        public uint Protect(ulong address, int size, uint protect) => _memory.Protect(address, size, protect);
        public void Flush(ulong address, int size) => _memory.FlushCode(address, size);
    }
}
