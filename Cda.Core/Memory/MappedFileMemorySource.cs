using System;
using System.IO;
using System.IO.MemoryMappedFiles;

namespace Cda.Core.Memory
{
    /// <summary>
    /// A read-only <see cref="IMemorySource"/> over a file on disk, backed by a
    /// memory-mapped view instead of a managed <c>byte[]</c> copy.
    ///
    /// The operating system pages the file in on demand, so a multi-gigabyte
    /// module can be browsed in the hex view with effectively no managed-heap
    /// cost and no up-front read — only the bytes actually looked at are faulted
    /// in. Addresses are file offsets (<see cref="MinAddress"/> = 0,
    /// <see cref="MaxAddress"/> = file length).
    ///
    /// This replaces holding an entire opened module in a
    /// <see cref="BufferMemorySource"/>, which pinned the whole image on the
    /// large-object heap for the life of the view and made large files exhaust
    /// memory (fatally so in the 32-bit build, where a single big managed array
    /// or whole-file mapping cannot fit the 2 GB user address space).
    /// </summary>
    public sealed class MappedFileMemorySource : IMemorySource, IDisposable
    {
        private readonly FileStream _file;
        private readonly MemoryMappedFile _map;
        private MemoryMappedViewAccessor _view;
        private long _viewOffset; // PointerOffset slack from view alignment
        private long _windowStart;
        private long _windowLength;
        private readonly long _length;
        private readonly object _viewGate = new();
        private bool _disposed;
        private const long WindowBytes = 64L * 1024 * 1024;

        public MappedFileMemorySource(string path, bool is64Bit)
        {
            Is64Bit = is64Bit;

            // Full sharing so a module that is currently loaded / running (a live
            // DLL or EXE) can still be mapped read-only.
            _file = new FileStream(path, FileMode.Open, FileAccess.Read,
                                   FileShare.ReadWrite | FileShare.Delete);
            _length = _file.Length;
            if (_length <= 0)
            {
                _file.Dispose();
                throw new InvalidOperationException("File is empty; nothing to map.");
            }

            try
            {
                // capacity 0 = map the whole file; leaveOpen so we own the stream's
                // lifetime explicitly and dispose it ourselves.
                _map = MemoryMappedFile.CreateFromFile(
                    _file, mapName: null, capacity: 0,
                    MemoryMappedFileAccess.Read, HandleInheritability.None, leaveOpen: true);
                _windowStart = 0;
                _windowLength = Math.Min(_length, WindowBytes);
                _view = _map.CreateViewAccessor(_windowStart, _windowLength, MemoryMappedFileAccess.Read);
                _viewOffset = _view.PointerOffset;
            }
            catch
            {
                _view?.Dispose();
                _map?.Dispose();
                _file.Dispose();
                throw;
            }
        }

        public bool Is64Bit { get; }
        public ulong MinAddress => 0;
        public ulong MaxAddress => (ulong)_length;

        /// <summary>Total mapped length in bytes.</summary>
        public long Length => _length;

        public unsafe int ReadMemory(ulong address, Span<byte> buffer)
        {
            if (_disposed || buffer.Length == 0 || address >= (ulong)_length) return 0;

            lock (_viewGate)
            {
                if (_disposed) return 0;
                long rel = (long)address;
                int total = 0;
                while (total < buffer.Length && rel < _length)
                {
                    EnsureWindow(rel);
                    int n = (int)Math.Min(
                        Math.Min((long)buffer.Length - total, _length - rel),
                        _windowStart + _windowLength - rel);
                    if (n <= 0) break;

                    var handle = _view.SafeMemoryMappedViewHandle;
                    byte* p = null;
                    handle.AcquirePointer(ref p);
                    try
                    {
                        new ReadOnlySpan<byte>(p + _viewOffset + (rel - _windowStart), n)
                            .CopyTo(buffer.Slice(total));
                    }
                    finally
                    {
                        if (p != null) handle.ReleasePointer();
                    }
                    total += n;
                    rel += n;
                }
                return total;
            }
        }

        private void EnsureWindow(long offset)
        {
            if (offset >= _windowStart && offset < _windowStart + _windowLength) return;
            _view.Dispose();
            _windowStart = offset;
            _windowLength = Math.Min(_length - _windowStart, WindowBytes);
            _view = _map.CreateViewAccessor(_windowStart, _windowLength, MemoryMappedFileAccess.Read);
            _viewOffset = _view.PointerOffset;
        }

        public void Dispose()
        {
            lock (_viewGate)
            {
                if (_disposed) return;
                _disposed = true;
                try { _view.Dispose(); } catch { }
                try { _map.Dispose(); } catch { }
                try { _file.Dispose(); } catch { }
            }
        }
    }
}
