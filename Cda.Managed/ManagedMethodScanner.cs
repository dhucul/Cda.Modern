using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Diagnostics.Runtime;

namespace Cda.Managed
{
    /// <summary>A JIT-compiled managed method discovered in a live target.</summary>
    public sealed class ManagedMethodInfo
    {
        public ulong NativeCode;       // native entry of the JIT-compiled body (0 ⇒ not yet JIT'd)
        public string FullName = "";   // Namespace.Type.Method
        public ulong ModuleImageBase;  // owning managed module's image base
        public string ModuleName = ""; // owning module file name
    }

    /// <summary>
    /// Discovers the <b>native</b> code addresses of JIT-compiled managed methods in a
    /// live .NET target, using ClrMD attached passively (read-only, not a debugger).
    /// This is what lets managed methods be instrumented by the exact same native
    /// inline-hook pipeline as native functions: each method's JIT'd entry is hooked
    /// like any other native function entry.
    ///
    /// Passive attach (<c>suspend: false</c>) reads target memory via ReadProcessMemory
    /// only, so it coexists with this engine's own debug loop / write handle / thread
    /// suspender. Methods JIT lazily, so this must be re-run periodically to pick up
    /// newly-compiled methods; tiered compilation can also re-JIT a method to a new
    /// address (launch the target with DOTNET_TieredCompilation=0 for stable addresses).
    /// </summary>
    public static class ManagedMethodScanner
    {
        /// <summary>True if the target hosts a CLR runtime (i.e. is a managed process).</summary>
        public static bool IsManaged(int pid)
        {
            try
            {
                using var dt = DataTarget.AttachToProcess(pid, suspend: false);
                return dt.ClrVersions.Length > 0;
            }
            catch { return false; }
        }

        /// <summary>
        /// Enumerate every method that currently has JIT-compiled native code. Only
        /// methods with <c>NativeCode != 0</c> are returned (a method not yet called has
        /// no native body to hook). Enumerate with the target's threads RUNNING — the
        /// DAC can deadlock against a suspended target — then suspend only for the hook
        /// install window.
        /// </summary>
        public static List<ManagedMethodInfo> ScanJitted(int pid, out string? error)
        {
            error = null;
            var result = new List<ManagedMethodInfo>();
            try
            {
                using var dt = DataTarget.AttachToProcess(pid, suspend: false);
                if (dt.ClrVersions.Length == 0) { error = "no CLR runtime in target (native or NativeAOT)"; return result; }

                using var runtime = dt.ClrVersions[0].CreateRuntime();
                runtime.FlushCachedData(); // see freshly-JIT'd methods on a re-scan

                foreach (var module in runtime.EnumerateModules())
                {
                    ulong imgBase = module.ImageBase;
                    string modName = SafeName(module);
                    foreach (var entry in module.EnumerateTypeDefToMethodTableMap())
                    {
                        ClrType? type;
                        try { type = runtime.GetTypeByMethodTable(entry.MethodTable); } catch { continue; }
                        if (type == null) continue;

                        foreach (var method in type.Methods)
                        {
                            ulong nc = method.NativeCode;
                            // 0 and ulong.MaxValue are both "no native body" sentinels
                            // ClrMD returns for a method not (yet) JIT-compiled.
                            if (nc == 0 || nc == ulong.MaxValue) continue;
                            result.Add(new ManagedMethodInfo
                            {
                                NativeCode = nc,
                                FullName = (type.Name ?? "?") + "." + (method.Name ?? "?"),
                                ModuleImageBase = imgBase,
                                ModuleName = modName,
                            });
                        }
                    }
                }
            }
            catch (Exception ex) { error = ex.Message; }
            return result;
        }

        /// <summary>Heuristic: is this a framework/runtime module (skip when hooking an
        /// app's own methods, to avoid drowning in System.*/Microsoft.* internals)?</summary>
        public static bool IsFrameworkModule(string moduleName)
        {
            // An unnamed/unresolvable module is dynamic/emitted code (Reflection.Emit,
            // expression trees, compiled Regex, dynamic proxies) — that is the app's OWN
            // work, so treat it as app (hookable), not framework. Only NAMED framework
            // modules below are excluded.
            if (string.IsNullOrEmpty(moduleName)) return false;
            string n = moduleName;
            return n.StartsWith("System.", StringComparison.OrdinalIgnoreCase)
                || n.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase)
                || n.StartsWith("netstandard", StringComparison.OrdinalIgnoreCase)
                || n.StartsWith("mscorlib", StringComparison.OrdinalIgnoreCase)
                || n.StartsWith("WindowsBase", StringComparison.OrdinalIgnoreCase)
                || n.StartsWith("PresentationCore", StringComparison.OrdinalIgnoreCase)
                || n.StartsWith("PresentationFramework", StringComparison.OrdinalIgnoreCase)
                || n.StartsWith("DirectWriteForwarder", StringComparison.OrdinalIgnoreCase);
        }

        private static string SafeName(ClrModule module)
        {
            try
            {
                string? p = module.Name ?? module.AssemblyName;
                return string.IsNullOrEmpty(p) ? "" : Path.GetFileName(p);
            }
            catch { return ""; }
        }
    }
}
