using System;

namespace Cda.Core.Memory
{
    /// <summary>
    /// A readable address space. Implemented by a live process (via
    /// ReadProcessMemory), by a byte buffer (file/snapshot), or by tests. The
    /// hex viewer and the PE inspector consume this so they are agnostic to
    /// whether the bytes come from disk or a running target.
    /// </summary>
    public interface IMemorySource
    {
        /// <summary>True for 64-bit address spaces.</summary>
        bool Is64Bit { get; }

        /// <summary>Lowest valid address (for clamping the hex view scrollbar).</summary>
        ulong MinAddress { get; }

        /// <summary>One past the highest valid address.</summary>
        ulong MaxAddress { get; }

        /// <summary>
        /// Read up to <paramref name="count"/> bytes at <paramref name="address"/>
        /// into <paramref name="buffer"/>. Returns the number of bytes actually
        /// read (0 on an unreadable region; never throws for unmapped memory).
        /// </summary>
        int ReadMemory(ulong address, Span<byte> buffer);
    }

    /// <summary>An address space that also supports writes (live patching).</summary>
    public interface IMemoryEditor : IMemorySource
    {
        /// <summary>Write bytes at an address. Returns the number written (0 on failure).</summary>
        int WriteMemory(ulong address, ReadOnlySpan<byte> data);
    }

    /// <summary>An <see cref="IMemorySource"/> backed by a fixed byte buffer.</summary>
    public sealed class BufferMemorySource : IMemoryEditor
    {
        private readonly byte[] _data;
        private readonly ulong _base;

        public BufferMemorySource(byte[] data, ulong baseAddress = 0, bool is64Bit = true)
        {
            _data = data;
            _base = baseAddress;
            Is64Bit = is64Bit;
        }

        public bool Is64Bit { get; }
        public ulong MinAddress => _base;
        public ulong MaxAddress => _base + (ulong)_data.Length;

        public int ReadMemory(ulong address, Span<byte> buffer)
        {
            if (address < _base) return 0;
            ulong rel = address - _base;
            if (rel >= (ulong)_data.Length) return 0;
            int avail = (int)Math.Min((ulong)buffer.Length, (ulong)_data.Length - rel);
            _data.AsSpan((int)rel, avail).CopyTo(buffer);
            return avail;
        }

        public int WriteMemory(ulong address, ReadOnlySpan<byte> data)
        {
            if (address < _base) return 0;
            ulong rel = address - _base;
            if (rel >= (ulong)_data.Length) return 0;
            int n = (int)Math.Min((ulong)data.Length, (ulong)_data.Length - rel);
            data.Slice(0, n).CopyTo(_data.AsSpan((int)rel, n));
            return n;
        }
    }
}
