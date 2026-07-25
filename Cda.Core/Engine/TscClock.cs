using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Calibrates the timestamp counter used by injected capture stubs against
    /// QueryPerformanceCounter (Stopwatch). The calibration runs once in the host;
    /// host and target observe the same hardware TSC frequency.
    /// </summary>
    internal static class TscClock
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate ulong ReadTsc();

        private static readonly Lazy<double> Frequency =
            new(Measure, LazyThreadSafetyMode.ExecutionAndPublication);

        public static double FrequencyHz => Frequency.Value;

        private static double Measure()
        {
            IntPtr code = NativeMethods.VirtualAlloc(IntPtr.Zero, (IntPtr)32,
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE,
                NativeMethods.PAGE_EXECUTE_READWRITE);
            if (code == IntPtr.Zero)
                return 1_000_000_000.0;

            try
            {
                // lfence; rdtsc; combine edx:eax into rax; ret.
                byte[] bytes = IntPtr.Size == 8
                    ? new byte[] { 0x0F, 0xAE, 0xE8, 0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x09, 0xD0, 0xC3 }
                    : new byte[] { 0x0F, 0xAE, 0xE8, 0x0F, 0x31, 0xC3 }; // x86 returns edx:eax
                Marshal.Copy(bytes, 0, code, bytes.Length);
                if (!NativeMethods.FlushInstructionCache(
                        NativeMethods.GetCurrentProcess(), code, (IntPtr)bytes.Length))
                    return 1_000_000_000.0;

                var read = Marshal.GetDelegateForFunctionPointer<ReadTsc>(code);
                var samples = new List<double>(5);
                for (int i = 0; i < 5; i++)
                {
                    long q0 = Stopwatch.GetTimestamp();
                    ulong t0 = read();
                    Thread.Sleep(20);
                    ulong t1 = read();
                    long q1 = Stopwatch.GetTimestamp();
                    long qDelta = q1 - q0;
                    if (qDelta <= 0 || t1 <= t0) continue;
                    samples.Add((t1 - t0) * (double)Stopwatch.Frequency / qDelta);
                }

                if (samples.Count == 0) return 1_000_000_000.0;
                samples.Sort();
                double hz = samples[samples.Count / 2];
                return double.IsFinite(hz) && hz >= 1_000_000 && hz <= 20_000_000_000
                    ? hz
                    : 1_000_000_000.0;
            }
            finally
            {
                NativeMethods.VirtualFree(code, IntPtr.Zero, NativeMethods.MEM_RELEASE);
            }
        }
    }
}
