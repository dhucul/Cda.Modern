using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Cda.Core.Process
{
    /// <summary>
    /// Suspends every thread of a target process for the duration of a delicate
    /// operation — installing or removing entry detours — then resumes them all
    /// on dispose. This removes the race where a target thread is executing the
    /// exact bytes being patched, which is a classic cause of crashes in inline
    /// hooking.
    ///
    /// Threads suspend at instruction boundaries, so after this returns no target
    /// thread is mid-instruction inside a patch site. New threads created during
    /// the (brief) window aren't covered; that residual risk is small and is the
    /// trade-off for not walking the loader's structures.
    /// </summary>
    public sealed class ThreadSuspender : IDisposable
    {
        private readonly List<IntPtr> _suspended = new();

        public ThreadSuspender(int pid)
        {
            IntPtr snap = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPTHREAD, 0);
            if (snap == NativeMethods.INVALID_HANDLE_VALUE) return;
            try
            {
                var te = new NativeMethods.THREADENTRY32
                {
                    dwSize = (uint)Marshal.SizeOf<NativeMethods.THREADENTRY32>(),
                };
                if (!NativeMethods.Thread32First(snap, ref te)) return;
                do
                {
                    if (te.th32OwnerProcessID != (uint)pid) continue;
                    IntPtr h = NativeMethods.OpenThread(NativeMethods.THREAD_SUSPEND_RESUME, false, te.th32ThreadID);
                    if (h == IntPtr.Zero) continue;
                    if (NativeMethods.SuspendThread(h) == unchecked((uint)-1))
                    {
                        NativeMethods.CloseHandle(h);
                        continue;
                    }
                    _suspended.Add(h);
                } while (NativeMethods.Thread32Next(snap, ref te));
            }
            finally
            {
                NativeMethods.CloseHandle(snap);
            }
        }

        public int Count => _suspended.Count;

        public void Dispose()
        {
            foreach (IntPtr h in _suspended)
            {
                NativeMethods.ResumeThread(h);
                NativeMethods.CloseHandle(h);
            }
            _suspended.Clear();
        }
    }
}
