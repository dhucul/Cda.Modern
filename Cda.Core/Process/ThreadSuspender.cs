using System;
using System.Collections.Generic;
using System.ComponentModel;
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
            if (snap == NativeMethods.INVALID_HANDLE_VALUE)
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "Could not enumerate target threads.");
            try
            {
                var te = new NativeMethods.THREADENTRY32
                {
                    dwSize = (uint)Marshal.SizeOf<NativeMethods.THREADENTRY32>(),
                };
                if (!NativeMethods.Thread32First(snap, ref te))
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "Could not enumerate target threads.");

                int matched = 0;
                while (true)
                {
                    if (te.th32OwnerProcessID == (uint)pid)
                    {
                        matched++;
                        IntPtr h = NativeMethods.OpenThread(NativeMethods.THREAD_SUSPEND_RESUME, false, te.th32ThreadID);
                        if (h == IntPtr.Zero)
                            throw new Win32Exception(Marshal.GetLastWin32Error(),
                                $"Could not open target thread {te.th32ThreadID}.");
                        if (NativeMethods.SuspendThread(h) == unchecked((uint)-1))
                        {
                            NativeMethods.CloseHandle(h);
                            throw new Win32Exception(Marshal.GetLastWin32Error(),
                                $"Could not suspend target thread {te.th32ThreadID}.");
                        }
                        _suspended.Add(h);
                    }

                    if (NativeMethods.Thread32Next(snap, ref te)) continue;
                    int error = Marshal.GetLastWin32Error();
                    if (error != NativeMethods.ERROR_NO_MORE_FILES)
                        throw new Win32Exception(error, "Target thread enumeration was incomplete.");
                    break;
                }

                if (matched == 0)
                    throw new InvalidOperationException("The target has no enumerable threads.");
            }
            catch
            {
                // Construction did not establish the all-threads-frozen invariant.
                // Undo every suspension already acquired before propagating failure.
                Dispose();
                throw;
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
