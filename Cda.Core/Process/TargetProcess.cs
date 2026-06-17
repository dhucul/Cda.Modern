using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Cda.Core.Memory;
using Cda.Core.Model;

namespace Cda.Core.Process
{
    /// <summary>
    /// A live, attached target process. Wraps OpenProcess + ReadProcessMemory +
    /// module enumeration and exposes the address space as an
    /// <see cref="IMemorySource"/>. This is the modern, 64-bit-capable, and
    /// cross-bitness (WOW64-aware) replacement for the legacy <c>oProcess</c> /
    /// <c>oMemoryFunctions</c> read path.
    ///
    /// Bitness note: an x64 host can read both x64 and x86 (WOW64) targets, so
    /// the recommended deployment opens any target from an x64 build and selects
    /// the decoder from <see cref="Is64Bit"/>.
    /// </summary>
    public sealed class TargetProcess : IMemoryEditor, IDisposable
    {
        private IntPtr _handle;

        /// <summary>Raw process handle, for engine-internal memory operations.</summary>
        internal IntPtr Handle => _handle;

        public int Pid { get; }
        public bool Is64Bit { get; private set; }
        public PeMachineKind TargetMachine { get; private set; }

        public ulong MinAddress => 0x10000;
        public ulong MaxAddress => Is64Bit ? 0x7FFFFFFFFFFFUL : 0x7FFFFFFFUL;

        /// <summary>
        /// Forcibly terminate a process by PID (best effort). Used by the startup
        /// trace's auto-bisection to discard a hidden test instance that ran clean.
        /// </summary>
        public static void Kill(int pid)
        {
            IntPtr h = NativeMethods.OpenProcess(NativeMethods.ProcessAccess.Terminate, false, pid);
            if (h == IntPtr.Zero) return;
            try { NativeMethods.TerminateProcess(h, 0xDEAD); }
            catch { /* best effort */ }
            finally { NativeMethods.CloseHandle(h); }
        }

        /// <summary>
        /// False once the target has exited. Uses GetExitCodeProcess, which works
        /// with the QueryLimitedInformation right we already hold. (A process whose
        /// real exit code is exactly STILL_ACTIVE/259 reads as alive — the safe
        /// default: we simply don't prematurely report an exit.)
        /// </summary>
        public bool IsAlive =>
            _handle != IntPtr.Zero &&
            NativeMethods.GetExitCodeProcess(_handle, out uint code) &&
            code == NativeMethods.STILL_ACTIVE;

        /// <summary>
        /// The target's exit code once it has exited (false while still running).
        /// A value of the form 0xCxxxxxxx is an NTSTATUS — the target crashed with
        /// that exception code rather than exiting normally.
        /// </summary>
        public bool TryGetExitCode(out uint code)
        {
            code = 0;
            return _handle != IntPtr.Zero
                && NativeMethods.GetExitCodeProcess(_handle, out code)
                && code != NativeMethods.STILL_ACTIVE;
        }

        public enum PeMachineKind { Unknown, X86, X64, Arm64 }

        private TargetProcess(int pid, IntPtr handle)
        {
            Pid = pid;
            _handle = handle;
        }

        public static TargetProcess Attach(int pid, bool forWrite = false)
        {
            var access = NativeMethods.ProcessAccess.QueryLimitedInformation |
                         NativeMethods.ProcessAccess.VmRead;
            if (forWrite)
                access |= NativeMethods.ProcessAccess.VmWrite | NativeMethods.ProcessAccess.VmOperation;

            IntPtr h = NativeMethods.OpenProcess(access, false, pid);
            if (h == IntPtr.Zero)
                throw new InvalidOperationException(
                    $"OpenProcess failed for PID {pid} (error {Marshal.GetLastWin32Error()}). " +
                    "Elevation may be required.");

            var tp = new TargetProcess(pid, h);
            tp.DetectBitness();
            return tp;
        }

        private void DetectBitness()
        {
            if (NativeMethods.IsWow64Process2(_handle, out ushort proc, out ushort native))
            {
                ushort machine = proc != NativeMethods.IMAGE_FILE_MACHINE_UNKNOWN ? proc : native;
                TargetMachine = machine switch
                {
                    NativeMethods.IMAGE_FILE_MACHINE_I386 => PeMachineKind.X86,
                    NativeMethods.IMAGE_FILE_MACHINE_AMD64 => PeMachineKind.X64,
                    NativeMethods.IMAGE_FILE_MACHINE_ARM64 => PeMachineKind.Arm64,
                    _ => PeMachineKind.Unknown,
                };
                Is64Bit = TargetMachine is PeMachineKind.X64 or PeMachineKind.Arm64;
            }
            else
            {
                // Fall back to the host bitness if the query is unavailable.
                Is64Bit = IntPtr.Size == 8;
                TargetMachine = Is64Bit ? PeMachineKind.X64 : PeMachineKind.X86;
            }
        }

        public int ReadMemory(ulong address, Span<byte> buffer)
        {
            if (_handle == IntPtr.Zero || buffer.Length == 0) return 0;
            byte[] tmp = new byte[buffer.Length];
            bool ok = NativeMethods.ReadProcessMemory(
                _handle, (IntPtr)unchecked((long)address), tmp, (IntPtr)tmp.Length, out IntPtr read);
            int n = ok ? (int)read : 0;
            if (n > 0) tmp.AsSpan(0, n).CopyTo(buffer);
            return n;
        }

        public int WriteMemory(ulong address, ReadOnlySpan<byte> data)
        {
            if (_handle == IntPtr.Zero || data.Length == 0) return 0;
            byte[] tmp = data.ToArray();
            bool ok = NativeMethods.WriteProcessMemory(
                _handle, (IntPtr)unchecked((long)address), tmp, (IntPtr)tmp.Length, out IntPtr written);
            return ok ? (int)written : 0;
        }

        /// <summary>Enumerate loaded modules (both 32- and 64-bit) as <see cref="ModuleInfo"/>.</summary>
        public List<ModuleInfo> EnumerateModules()
        {
            var result = new List<ModuleInfo>();
            uint needed;
            // First call to size the array.
            NativeMethods.EnumProcessModulesEx(_handle, Array.Empty<IntPtr>(), 0, out needed,
                NativeMethods.LIST_MODULES_ALL);
            if (needed == 0) return result;

            int count = (int)(needed / (uint)IntPtr.Size);
            var mods = new IntPtr[count];
            if (!NativeMethods.EnumProcessModulesEx(_handle, mods, needed, out needed,
                    NativeMethods.LIST_MODULES_ALL))
                return result;

            var name = new char[260];
            foreach (var m in mods)
            {
                if (m == IntPtr.Zero) continue;
                uint len = NativeMethods.GetModuleFileNameExW(_handle, m, name, (uint)name.Length);
                string path = len > 0 ? new string(name, 0, (int)len) : "";
                string shortName = path.Length > 0 ? System.IO.Path.GetFileName(path) : "0x" + m.ToString("X");

                ulong size = 0;
                if (NativeMethods.GetModuleInformation(_handle, m, out var info,
                        (uint)Marshal.SizeOf<NativeMethods.MODULEINFO>()))
                    size = info.SizeOfImage;

                result.Add(new ModuleInfo(shortName, (ulong)m.ToInt64(), size, path));
            }
            return result;
        }

        public void Dispose()
        {
            if (_handle != IntPtr.Zero)
            {
                NativeMethods.CloseHandle(_handle);
                _handle = IntPtr.Zero;
            }
        }
    }
}
