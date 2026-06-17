using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Cda.Core.Model;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Resolves code addresses to function names via DbgHelp, using whatever
    /// symbol information is already on the machine — a module's PDB sitting next
    /// to it, or its export table. This is what names internal (non-exported)
    /// functions that the static call scan can only label <c>sub_XXXX</c>, when a
    /// matching PDB is present.
    ///
    /// Deliberately conservative:
    ///   * it never configures a symbol <i>server</i>, so it performs no network
    ///     access and cannot hang downloading symbols — only local symbols are used;
    ///   * a name is accepted only when it lands exactly on the queried address
    ///     (displacement 0), so an internal function is never mislabeled with the
    ///     name of a nearby export from a symbol-less module.
    ///
    /// DbgHelp is not thread-safe: a resolver must be used from a single thread at
    /// a time. The intended use is to create one, name a discovery pass, and
    /// dispose it — see <see cref="NameUnnamed"/>.
    /// </summary>
    public sealed class SymbolResolver : IDisposable
    {
        private readonly IntPtr _handle;
        private bool _initialized;
        private readonly HashSet<ulong> _loaded = new();

        private SymbolResolver(IntPtr handle) => _handle = handle;

        /// <summary>
        /// Initialize DbgHelp against the target process handle, or return null if
        /// DbgHelp is unavailable / initialization fails (callers treat symbols as
        /// best-effort and carry on without them).
        /// </summary>
        public static SymbolResolver? TryCreate(TargetProcess process)
        {
            IntPtr h = process.Handle;
            if (h == IntPtr.Zero) return null;
            try
            {
                // Undecorate names, defer PDB loading until a module is queried,
                // never prompt, and fail fast. Pass an EMPTY search path, NOT null:
                // a null path makes DbgHelp fall back to the _NT_SYMBOL_PATH
                // environment variable, which on a developer machine usually points
                // at a symbol *server* — attaching would then hang for seconds to
                // minutes downloading PDBs over the network. An empty path keeps it
                // strictly local (a PDB next to the module, or the path embedded in
                // the image), so attach stays fast and offline.
                SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS |
                              SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS |
                              SYMOPT_CASE_INSENSITIVE);
                if (!SymInitializeW(h, "", false)) return null;
                return new SymbolResolver(h) { _initialized = true };
            }
            catch (DllNotFoundException) { return null; }
            catch (EntryPointNotFoundException) { return null; }
        }

        /// <summary>Register a module so its symbols can be resolved. Cheap (deferred).</summary>
        public void LoadModule(ModuleInfo m)
        {
            if (!_initialized || m.BaseAddress == 0) return;
            if (!_loaded.Add(m.BaseAddress)) return;
            // A null/empty image name lets DbgHelp read the PE header from the live
            // process at BaseOfDll to locate the matching PDB; a real path is used
            // when known. Size 0 means "read it from the header".
            string? image = string.IsNullOrEmpty(m.Path) ? null : m.Path;
            try { SymLoadModuleExW(_handle, IntPtr.Zero, image, null, m.BaseAddress, (uint)m.Size, IntPtr.Zero, 0); }
            catch { /* best-effort */ }
        }

        /// <summary>
        /// Resolve <paramref name="address"/> to a symbol name + displacement from
        /// the symbol start. Returns false if no symbol is known.
        /// </summary>
        public bool TryResolve(ulong address, out string name, out ulong displacement)
        {
            name = "";
            displacement = 0;
            if (!_initialized) return false;

            int headerSize = Marshal.SizeOf<SYMBOL_INFO>();
            int nameOffset = (int)Marshal.OffsetOf<SYMBOL_INFO>(nameof(SYMBOL_INFO.MaxNameLen)) + sizeof(uint);
            int bufSize = headerSize + MaxNameLen * 2; // trailing WCHAR Name[MaxNameLen]

            IntPtr buf = Marshal.AllocHGlobal(bufSize);
            try
            {
                for (int i = 0; i < bufSize; i++) Marshal.WriteByte(buf, i, 0);
                var info = new SYMBOL_INFO
                {
                    SizeOfStruct = (uint)headerSize,
                    MaxNameLen = (uint)MaxNameLen,
                };
                Marshal.StructureToPtr(info, buf, false);

                if (!SymFromAddrW(_handle, address, out ulong disp, buf)) return false;

                string? s = Marshal.PtrToStringUni(IntPtr.Add(buf, nameOffset));
                if (string.IsNullOrEmpty(s)) return false;

                name = s!;
                displacement = disp;
                return true;
            }
            catch { return false; }
            finally { Marshal.FreeHGlobal(buf); }
        }

        /// <summary>
        /// Fill in names for the functions a scan left unnamed, using locally
        /// available symbols. Only exact entry-point matches (displacement 0) are
        /// applied, so an internal function is never given a nearby export's name.
        /// Best-effort and bounded; any DbgHelp failure leaves names untouched.
        /// Returns how many functions were newly named.
        /// </summary>
        public static int NameUnnamed(TargetProcess process, TraceDataset dataset, int max = 20000)
        {
            using var r = TryCreate(process);
            if (r == null) return 0;

            foreach (var m in dataset.Modules) r.LoadModule(m);

            int named = 0, tried = 0;
            foreach (var f in dataset.Functions)
            {
                if (!string.IsNullOrEmpty(f.Name)) continue;
                if (tried++ >= max) break;
                if (r.TryResolve(f.Address, out string name, out ulong disp) && disp == 0)
                {
                    f.Name = name;
                    named++;
                }
            }
            return named;
        }

        public void Dispose()
        {
            if (_initialized)
            {
                try { SymCleanup(_handle); } catch { /* ignore */ }
                _initialized = false;
            }
        }

        // --- DbgHelp interop -------------------------------------------------

        private const int MaxNameLen = 256;

        private const uint SYMOPT_CASE_INSENSITIVE = 0x00000001;
        private const uint SYMOPT_UNDNAME = 0x00000002;
        private const uint SYMOPT_DEFERRED_LOADS = 0x00000004;
        private const uint SYMOPT_FAIL_CRITICAL_ERRORS = 0x00000200;
        private const uint SYMOPT_NO_PROMPTS = 0x00080000;

        // SYMBOL_INFO(W) fixed header. The variable-length Name[] follows in the
        // over-allocated buffer and is read manually (see TryResolve).
        [StructLayout(LayoutKind.Sequential)]
        private struct SYMBOL_INFO
        {
            public uint SizeOfStruct;
            public uint TypeIndex;
            public ulong Reserved0;
            public ulong Reserved1;
            public uint Index;
            public uint Size;
            public ulong ModBase;
            public uint Flags;
            public ulong Value;
            public ulong Address;
            public uint Register;
            public uint Scope;
            public uint Tag;
            public uint NameLen;
            public uint MaxNameLen;
        }

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool SymInitializeW(IntPtr hProcess, string? UserSearchPath, bool fInvadeProcess);

        [DllImport("dbghelp.dll")]
        private static extern uint SymSetOptions(uint SymOptions);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ulong SymLoadModuleExW(
            IntPtr hProcess, IntPtr hFile, string? ImageName, string? ModuleName,
            ulong BaseOfDll, uint DllSize, IntPtr Data, uint Flags);

        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern bool SymFromAddrW(IntPtr hProcess, ulong Address, out ulong Displacement, IntPtr Symbol);

        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern bool SymCleanup(IntPtr hProcess);
    }
}
