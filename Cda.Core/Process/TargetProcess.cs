using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Cda.Core.Memory;
using Cda.Core.Model;
using Cda.Core.Pe;

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
        // IMemorySource bounds are half-open: this is one past the highest
        // user-mode address represented by the selected decoder/address space.
        public ulong MaxAddress => Is64Bit ? 0x0000800000000000UL : 0x0000000100000000UL;

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
                access |= NativeMethods.ProcessAccess.VmWrite | NativeMethods.ProcessAccess.VmOperation
                        | NativeMethods.ProcessAccess.CreateThread; // to register the return-capture VEH remotely

            IntPtr h = NativeMethods.OpenProcess(access, false, pid);
            if (h == IntPtr.Zero)
                throw new InvalidOperationException(
                    $"OpenProcess failed for PID {pid} (error {Marshal.GetLastWin32Error()}). " +
                    "Elevation may be required.");

            var tp = new TargetProcess(pid, h);
            try
            {
                tp.DetectBitness();
                return tp;
            }
            catch
            {
                tp.Dispose();
                throw;
            }
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
            NativeMethods.ReadProcessMemory(
                _handle, NativeMethods.ToIntPtr(address), tmp, (IntPtr)tmp.Length, out IntPtr read);
            long got = read.ToInt64();
            int n = got > 0 ? (int)Math.Min(got, buffer.Length) : 0;
            if (n > 0) tmp.AsSpan(0, n).CopyTo(buffer);
            return n;
        }

        public int WriteMemory(ulong address, ReadOnlySpan<byte> data)
        {
            if (_handle == IntPtr.Zero || data.Length == 0) return 0;
            byte[] tmp = data.ToArray();
            bool ok = NativeMethods.WriteProcessMemory(
                _handle, NativeMethods.ToIntPtr(address), tmp, (IntPtr)tmp.Length, out IntPtr written);
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

            IntPtr[] mods = Array.Empty<IntPtr>();
            uint returnedBytes = 0;
            for (int attempt = 0; attempt < 8; attempt++)
            {
                ulong count64 = ((ulong)needed + (uint)IntPtr.Size - 1) / (uint)IntPtr.Size;
                if (count64 == 0 || count64 > 1_000_000)
                    return result;

                mods = new IntPtr[(int)count64];
                uint capacityBytes = checked((uint)(mods.Length * IntPtr.Size));
                if (!NativeMethods.EnumProcessModulesEx(_handle, mods, capacityBytes,
                        out returnedBytes, NativeMethods.LIST_MODULES_ALL))
                    return result;

                // Modules can load between the sizing and fill calls. Retry with the
                // newly reported size instead of silently returning a truncated map.
                if (returnedBytes <= capacityBytes)
                    break;
                needed = returnedBytes;
            }

            if (mods.Length == 0 || returnedBytes > (ulong)mods.Length * (uint)IntPtr.Size)
                return result;
            int returnedCount = Math.Min(mods.Length, (int)(returnedBytes / (uint)IntPtr.Size));

            for (int moduleIndex = 0; moduleIndex < returnedCount; moduleIndex++)
            {
                IntPtr m = mods[moduleIndex];
                if (m == IntPtr.Zero) continue;
                string path = ReadModulePath(m);
                string shortName = path.Length > 0 ? System.IO.Path.GetFileName(path) : "0x" + m.ToString("X");

                ulong size = 0;
                if (NativeMethods.GetModuleInformation(_handle, m, out var info,
                        (uint)Marshal.SizeOf<NativeMethods.MODULEINFO>()))
                    size = info.SizeOfImage;

                ulong moduleBase = NativeMethods.ToUInt64(m);
                ulong preferredBase = 0;
                try
                {
                    // Populate the link-time base at enumeration time so every live
                    // x86/x64 capture path can present static-disassembler addresses,
                    // even when that module is not subsequently call-site scanned.
                    byte[] header = new byte[0x1000];
                    int read = ReadMemory(moduleBase, header);
                    if (read >= 0x200)
                        preferredBase = PeImage.FromMappedImage(header, moduleBase).PreferredImageBase;
                }
                catch { /* malformed or unreadable module: live VA remains usable */ }

                result.Add(new ModuleInfo(shortName, moduleBase, size, path,
                    preferredBaseAddress: preferredBase));
            }
            return result;
        }

        private string ReadModulePath(IntPtr module)
        {
            for (int capacity = 260; ;)
            {
                var buffer = new char[capacity];
                uint length = NativeMethods.GetModuleFileNameExW(
                    _handle, module, buffer, (uint)buffer.Length);
                if (length == 0) return "";
                if (length < buffer.Length)
                    return new string(buffer, 0, (int)length);
                if (capacity == 32_768) return "";
                capacity = Math.Min(capacity * 2, 32_768);
            }
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
