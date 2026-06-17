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
        public ulong GetImageBase()
        {
            var pbi = new NativeMethods.PROCESS_BASIC_INFORMATION();
            int status = NativeMethods.NtQueryInformationProcess(
                _hProcess, 0 /* ProcessBasicInformation */, ref pbi,
                Marshal.SizeOf<NativeMethods.PROCESS_BASIC_INFORMATION>(), out _);
            if (status != 0 || pbi.PebBaseAddress == IntPtr.Zero) return 0;

            // PEB->ImageBaseAddress is at +0x10 on x64.
            byte[] baseBuf = new byte[8];
            if (!NativeMethods.ReadProcessMemory(_hProcess, pbi.PebBaseAddress + 0x10, baseBuf, (IntPtr)8, out _))
                return 0;
            ulong imageBase = BitConverter.ToUInt64(baseBuf, 0);
            if (imageBase == 0) return 0;

            // Validate: the image must start with 'MZ'.
            byte[] mz = new byte[2];
            if (!NativeMethods.ReadProcessMemory(_hProcess, (IntPtr)unchecked((long)imageBase), mz, (IntPtr)2, out _))
                return 0;
            if (mz[0] != 0x4D || mz[1] != 0x5A) return 0; // 'M','Z'
            return imageBase;
        }

        public void Resume() => NativeMethods.ResumeThread(_hThread);

        public void Dispose()
        {
            if (_hThread != IntPtr.Zero) { NativeMethods.CloseHandle(_hThread); _hThread = IntPtr.Zero; }
            if (_hProcess != IntPtr.Zero) { NativeMethods.CloseHandle(_hProcess); _hProcess = IntPtr.Zero; }
        }
    }
}
