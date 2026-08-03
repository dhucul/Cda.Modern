using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Cda.Core.Process
{
    /// <summary>
    /// Launches an executable in the suspended state (CREATE_SUSPENDED) so the
    /// caller can instrument it BEFORE its first instruction runs, then resume it.
    /// This is what makes "capture from the moment the program starts" possible —
    /// the hooks are armed while the process is frozen at creation, before the
    /// loader has even handed control to the entry point.
    ///
    /// The actual (ASLR-relocated) image base is read from the PEB and validated
    /// against the 'MZ' signature, so the entry-point VA can be computed reliably.
    /// </summary>
    public sealed class SuspendedProcess : IDisposable
    {
        public int Pid { get; }
        private IntPtr _hProcess;
        private IntPtr _hThread;
        private bool _resumed;

        private SuspendedProcess(int pid, IntPtr hProcess, IntPtr hThread)
        {
            Pid = pid;
            _hProcess = hProcess;
            _hThread = hThread;
        }

        /// <summary>
        /// Create the target suspended. When <paramref name="hidden"/> is true it is
        /// launched with its window hidden (and no console) — used for auto-bisection
        /// test runs so a repeatedly relaunched target doesn't pop up or steal focus.
        /// When <paramref name="disableAslr"/> is true the target is launched with
        /// bottom-up + high-entropy ASLR forced off (a per-process mitigation policy),
        /// so its modules load at the same base every run and the captured absolute
        /// addresses are reproducible across runs and saved traces.
        /// </summary>
        public static SuspendedProcess Create(string path, bool hidden = false, bool disableAslr = false)
        {
            string cmdLine = "\"" + path + "\"";
            string? workDir = Path.GetDirectoryName(path);

            bool ok = NativeMethods.CreateProcessGuarded(
                path, cmdLine, NativeMethods.CREATE_SUSPENDED, workDir,
                disableAslr, hidden, out NativeMethods.PROCESS_INFORMATION pi);

            if (!ok)
                throw new InvalidOperationException(
                    $"CreateProcess failed (error {Marshal.GetLastWin32Error()}).");

            return new SuspendedProcess((int)pi.dwProcessId, pi.hProcess, pi.hThread);
        }

        /// <summary>
        /// The ASLR-relocated base of the main image, or 0 if it can't be resolved
        /// or doesn't validate as a PE ('MZ'). Reads PEB-&gt;ImageBaseAddress.
        /// </summary>
        public ulong GetImageBase() => GetImageBase(out _);

        /// <summary>
        /// Resolve the main image base and return a compact failure reason when
        /// Windows does not expose a readable/valid PEB image pointer.
        /// </summary>
        public ulong GetImageBase(out string diagnostic)
        {
            bool targetIs32Bit = IntPtr.Size == 4;
            if (NativeMethods.IsWow64Process2(_hProcess, out ushort processMachine, out ushort nativeMachine))
                targetIs32Bit = processMachine == NativeMethods.IMAGE_FILE_MACHINE_I386 ||
                    (processMachine == NativeMethods.IMAGE_FILE_MACHINE_UNKNOWN &&
                     nativeMachine == NativeMethods.IMAGE_FILE_MACHINE_I386);

            IntPtr pebAddress;
            int status;
            int returned;
            bool useWow64Peb = IntPtr.Size == 8 && targetIs32Bit;
            if (useWow64Peb)
            {
                status = NativeMethods.NtQueryInformationProcessPointer(
                    _hProcess, NativeMethods.ProcessWow64Information,
                    out pebAddress, IntPtr.Size, out returned);
            }
            else
            {
                var pbi = new NativeMethods.PROCESS_BASIC_INFORMATION();
                status = NativeMethods.NtQueryInformationProcess(
                    _hProcess, 0 /* ProcessBasicInformation */, ref pbi,
                    Marshal.SizeOf<NativeMethods.PROCESS_BASIC_INFORMATION>(), out returned);
                pebAddress = pbi.PebBaseAddress;
            }

            if (status != 0 || pebAddress == IntPtr.Zero)
            {
                diagnostic = $"NtQueryInformationProcess status=0x{status:X8}, returned={returned}, PEB=0x{NativeMethods.ToUInt64(pebAddress):X}, WOW64={useWow64Peb}";
                return 0;
            }

            // PEB->ImageBaseAddress is pointer-sized and has a different offset in
            // the two layouts: +0x08 on x86, +0x10 on x64. A 64-bit host launching
            // PE32 has two PEBs; ProcessWow64Information above selects PEB32.
            int pointerSize = targetIs32Bit ? 4 : 8;
            int imageBaseOffset = targetIs32Bit ? 0x08 : 0x10;
            byte[] baseBuf = new byte[pointerSize];
            if (!NativeMethods.ReadProcessMemory(_hProcess,
                    pebAddress + imageBaseOffset, baseBuf,
                    (IntPtr)pointerSize, out IntPtr bytesRead) ||
                bytesRead.ToInt64() != pointerSize)
            {
                diagnostic = $"PEB image-base read failed (error {Marshal.GetLastWin32Error()}, PEB=0x{NativeMethods.ToUInt64(pebAddress):X}, offset=0x{imageBaseOffset:X}, read={bytesRead.ToInt64()}/{pointerSize})";
                return 0;
            }
            ulong imageBase = pointerSize == 4
                ? BitConverter.ToUInt32(baseBuf, 0)
                : BitConverter.ToUInt64(baseBuf, 0);
            if (imageBase == 0)
            {
                diagnostic = $"PEB image-base pointer was zero (PEB=0x{NativeMethods.ToUInt64(pebAddress):X}, offset=0x{imageBaseOffset:X})";
                return 0;
            }

            // Validate: the image must start with 'MZ'.
            byte[] mz = new byte[2];
            if (!NativeMethods.ReadProcessMemory(_hProcess, NativeMethods.ToIntPtr(imageBase),
                    mz, (IntPtr)2, out _))
            {
                diagnostic = $"image base 0x{imageBase:X} was unreadable (error {Marshal.GetLastWin32Error()})";
                return 0;
            }
            if (mz[0] != 0x4D || mz[1] != 0x5A)
            {
                diagnostic = $"image base 0x{imageBase:X} did not contain MZ (bytes {mz[0]:X2} {mz[1]:X2})";
                return 0;
            }
            diagnostic = $"PEB=0x{NativeMethods.ToUInt64(pebAddress):X}, offset=0x{imageBaseOffset:X}, WOW64={useWow64Peb}";
            return imageBase;
        }

        public void Resume()
        {
            uint previous = NativeMethods.ResumeThread(_hThread);
            if (previous == uint.MaxValue)
                throw new System.ComponentModel.Win32Exception(
                    Marshal.GetLastWin32Error(), "Could not resume the launched target.");
            _resumed = true;
        }

        public void Dispose()
        {
            IntPtr thread = System.Threading.Interlocked.Exchange(ref _hThread, IntPtr.Zero);
            if (!_resumed && thread != IntPtr.Zero)
            {
                try { NativeMethods.ResumeThread(thread); } catch { }
                _resumed = true;
            }
            if (thread != IntPtr.Zero) NativeMethods.CloseHandle(thread);
            IntPtr process = System.Threading.Interlocked.Exchange(ref _hProcess, IntPtr.Zero);
            if (process != IntPtr.Zero) NativeMethods.CloseHandle(process);
            GC.SuppressFinalize(this);
        }

        ~SuspendedProcess() => Dispose();
    }
}
