using System.Collections.Generic;

namespace Cda.Core.Model
{
    /// <summary>A loaded module in the target address space. 64-bit safe.</summary>
    public sealed class ModuleInfo
    {
        public string Name;
        public ulong BaseAddress;
        public ulong Size;

        /// <summary>Full path on disk, when known (used by the PE inspector / hex view).</summary>
        public string? Path;

        public ModuleInfo(string name, ulong baseAddress, ulong size, string? path = null)
        {
            Name = name;
            BaseAddress = baseAddress;
            Size = size;
            Path = path;
        }

        public bool Contains(ulong address) =>
            address >= BaseAddress && address < BaseAddress + Size;
    }

    /// <summary>
    /// A discovered function in the target. The slim view the graph and the
    /// function list need; the engine's instrumentation state lives elsewhere.
    /// </summary>
    public sealed class TracedFunction
    {
        public ulong Address;
        public string? Name;
        public ulong ModuleBase;

        /// <summary>How many times the function was observed (filled by capture).</summary>
        public long CallCount;

        public TracedFunction(ulong address, ulong moduleBase, string? name = null)
        {
            Address = address;
            ModuleBase = moduleBase;
            Name = name;
        }

        public string DisplayName =>
            string.IsNullOrEmpty(Name) ? "sub_" + Address.ToString("X") : Name!;
    }

    /// <summary>Convenience container produced by the engine (or the demo feeder).</summary>
    public sealed class TraceDataset
    {
        public List<ModuleInfo> Modules = new();
        public List<TracedFunction> Functions = new();
        public List<CallRecord> Records = new();

        public double TimeStart;
        public double TimeEnd;
    }
}
