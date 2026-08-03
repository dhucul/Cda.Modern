using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Cda.Core.Process
{
    /// <summary>
    /// Suspends a target process for a short code-patching critical section.
    /// Process suspension is used instead of a one-time thread snapshot so a
    /// concurrently-created thread cannot run through a partially written detour.
    /// </summary>
    public sealed class ThreadSuspender : IDisposable
    {
        private IntPtr _process;
        private bool _suspended;
        public bool ResumeFailed { get; private set; }

        public ThreadSuspender(int pid)
        {
            _process = NativeMethods.OpenProcess(
                NativeMethods.ProcessAccess.SuspendResume |
                NativeMethods.ProcessAccess.QueryLimitedInformation,
                false, pid);
            if (_process == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    $"Could not open target process {pid} for suspension.");

            int status = NativeMethods.NtSuspendProcess(_process);
            if (status != 0)
            {
                uint error = NativeMethods.RtlNtStatusToDosError(status);
                NativeMethods.CloseHandle(_process);
                _process = IntPtr.Zero;
                throw new Win32Exception(unchecked((int)error),
                    $"Could not suspend target process {pid} (NTSTATUS 0x{status:X8}).");
            }
            _suspended = true;
        }

        // Kept for diagnostic compatibility with the former per-thread
        // implementation. A process-level suspension is one owned operation.
        public int Count => _suspended ? 1 : 0;

        public void Dispose()
        {
            if (_process == IntPtr.Zero) return;
            if (_suspended)
            {
                int status = NativeMethods.NtResumeProcess(_process);
                for (int retry = 0; status != 0 && retry < 3; retry++)
                {
                    System.Threading.Thread.Sleep(5);
                    status = NativeMethods.NtResumeProcess(_process);
                }
                ResumeFailed = status != 0;
                _suspended = false;
            }

            try { NativeMethods.CloseHandle(_process); } catch { }
            _process = IntPtr.Zero;
            GC.SuppressFinalize(this);
        }

        ~ThreadSuspender()
        {
            IntPtr process = _process;
            if (process == IntPtr.Zero) return;
            if (_suspended)
            {
                try { NativeMethods.NtResumeProcess(process); } catch { }
            }
            try { NativeMethods.CloseHandle(process); } catch { }
            _process = IntPtr.Zero;
            _suspended = false;
        }
    }
}
