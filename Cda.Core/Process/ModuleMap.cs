using System;
using System.Collections.Generic;
using Cda.Core.Model;

namespace Cda.Core.Process
{
    /// <summary>
    /// Maps an arbitrary address to the module that owns it. Modern replacement
    /// for the legacy <c>oModuleLookup</c> / <c>HEAP_INFO</c> map, using a sorted
    /// base-address array and binary search instead of a linear scan.
    /// </summary>
    public sealed class ModuleMap
    {
        private readonly List<ModuleInfo> _modules;
        private readonly ulong[] _bases;

        public ModuleMap(IEnumerable<ModuleInfo> modules)
        {
            _modules = new List<ModuleInfo>(modules);
            _modules.Sort((a, b) => a.BaseAddress.CompareTo(b.BaseAddress));
            _bases = new ulong[_modules.Count];
            for (int i = 0; i < _modules.Count; i++) _bases[i] = _modules[i].BaseAddress;
        }

        public IReadOnlyList<ModuleInfo> Modules => _modules;

        public ModuleInfo? Resolve(ulong address)
        {
            if (_bases.Length == 0) return null;
            int i = Array.BinarySearch(_bases, address);
            if (i < 0) i = ~i - 1;
            if (i < 0) return null;
            var m = _modules[i];
            return m.Contains(address) ? m : null;
        }

        /// <summary>Format an address as <c>module+0xRVA</c> for display.</summary>
        public string Describe(ulong address)
        {
            var m = Resolve(address);
            if (m == null) return "0x" + address.ToString("X");
            return $"{m.Name}+0x{(address - m.BaseAddress):X}";
        }
    }
}
