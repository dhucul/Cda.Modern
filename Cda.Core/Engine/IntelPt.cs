using System;
using System.Runtime.InteropServices;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Thin wrapper over the Windows inbox Intel Processor Trace driver (<c>ipt.sys</c>,
    /// device <c>\\.\Ipt</c>) — the always-on branch-history source used to confirm a
    /// dialog's gating branch on its FIRST occurrence (where the DR-breakpoint path can
    /// only confirm on the next run). The IOCTL interface is undocumented but stable
    /// (reverse-engineered by Ionescu's WinIPT and verified byte-for-byte on this build):
    ///
    ///   IPT_INPUT_BUFFER (0x30): BufferMajorVersion(u32)@0=1, BufferMinorVersion@4=0,
    ///     InputType@8, union@0x10. StartProcessTrace: ProcessHandle@0x10, Options@0x18.
    ///     Get{Size,Trace}: TraceVersion(u16)@0x10, ProcessHandle@0x18.
    ///   Options (IPT_OPTIONS): OptionVersion:4=1, TimingSettings:4, MtcFreq:4, CycThresh:4,
    ///     TopaPagesPow2:4 (buffer = 4KB·2^n), MatchSettings:3, Inherit:1, ModeSettings:4.
    ///   IOCTLs: IPT_REQUEST 0x220004 (buffered), IPT_READ_TRACE 0x220006 (out-direct).
    ///
    /// Intel-only; if the driver/service/device is absent (AMD, disabled) TryCreate returns
    /// null and the caller falls back to the DR+EFLAGS path. See <see cref="PtDecoder"/> for
    /// turning the returned buffer into gating-branch directions.
    /// </summary>
    public sealed class IntelPt : IDisposable
    {
        private const uint IOCTL_IPT_REQUEST = 0x220004, IOCTL_IPT_READ_TRACE = 0x220006;
        private const uint TypeGetProcessTraceSize = 1, TypeGetProcessTrace = 2, TypeStartProcessTrace = 5, TypeStopProcessTrace = 6;
        private const ushort TraceVersionCurrent = 1;
        // OptionVersion=1, no timing, TopaPagesPow2=13 (32 MB per thread — large so the
        // pre-dialog branch history survives the window-creation flood before a poll-time
        // read; a wrapped ring is the main reason a first-occurrence gate can't be found),
        // user-mode only.
        private const ulong Options = 0x1UL | (13UL << 16);

        private static readonly IntPtr InvalidHandle = new(-1);

        private IntPtr _device = InvalidHandle;
        private IntPtr _hProcess = IntPtr.Zero;
        private bool _tracing;

        public bool IsOpen => _device != InvalidHandle && _device != IntPtr.Zero;

        /// <summary>
        /// Ensure the inbox IPT service is running (so <c>\\.\Ipt</c> exists), open the
        /// device, and validate the interface with IptGetTraceVersion. Returns null (with a
        /// reason) on any failure — the caller then uses the DR fallback.
        /// </summary>
        public static IntelPt? TryCreate(out string? reason)
        {
            if (!EnsureService(out reason)) return null;
            IntPtr dev = NativeMethods.CreateFileW(@"\\.\Ipt",
                NativeMethods.GENERIC_READ | NativeMethods.GENERIC_WRITE,
                NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE,
                IntPtr.Zero, NativeMethods.OPEN_EXISTING, 0, IntPtr.Zero);
            if (dev == InvalidHandle || dev == IntPtr.Zero) { reason = $"open \\.\\Ipt failed ({Marshal.GetLastWin32Error()})"; return null; }
            var pt = new IntelPt { _device = dev };
            if (!pt.GetTraceVersion(out int tv) || tv == 0) { reason = "IptGetTraceVersion failed — unexpected interface"; pt.Dispose(); return null; }
            reason = null;
            return pt;
        }

        // Start the inbox "Ipt" service (idempotent). Requires elevation, which the app has.
        private static bool EnsureService(out string? reason)
        {
            reason = null;
            IntPtr scm = NativeMethods.OpenSCManagerW(null, null, NativeMethods.SC_MANAGER_CONNECT);
            if (scm == IntPtr.Zero) { reason = $"OpenSCManager failed ({Marshal.GetLastWin32Error()})"; return false; }
            try
            {
                IntPtr svc = NativeMethods.OpenServiceW(scm, "Ipt", NativeMethods.SERVICE_START | NativeMethods.SERVICE_QUERY_STATUS);
                if (svc == IntPtr.Zero) { reason = "IPT service absent (no Intel PT support)"; return false; }
                try
                {
                    if (NativeMethods.QueryServiceStatus(svc, out var st) &&
                        (st.dwCurrentState == NativeMethods.SERVICE_RUNNING || st.dwCurrentState == NativeMethods.SERVICE_START_PENDING))
                        return true;
                    if (NativeMethods.StartServiceW(svc, 0, IntPtr.Zero)) return true;
                    int err = Marshal.GetLastWin32Error();
                    if (err == NativeMethods.ERROR_SERVICE_ALREADY_RUNNING) return true;
                    reason = $"StartService(Ipt) failed ({err})";
                    return false;
                }
                finally { NativeMethods.CloseServiceHandle(svc); }
            }
            finally { NativeMethods.CloseServiceHandle(scm); }
        }

        private static byte[] Input(uint type, Action<byte[]>? fillUnion = null)
        {
            var b = new byte[0x30];
            BitConverter.GetBytes(1u).CopyTo(b, 0);   // BufferMajorVersion = 1
            BitConverter.GetBytes(type).CopyTo(b, 8); // InputType (union at 0x10)
            fillUnion?.Invoke(b);
            return b;
        }

        private bool Request(byte[] input, byte[]? output) =>
            NativeMethods.DeviceIoControl(_device, IOCTL_IPT_REQUEST, input, (uint)input.Length,
                output, (uint)(output?.Length ?? 0), out _, IntPtr.Zero);

        private bool GetTraceVersion(out int version)
        {
            var o = new byte[0x18];
            bool ok = Request(Input(0 /* IptGetTraceVersion */), o);
            version = ok ? BitConverter.ToUInt16(o, 0) : 0;
            return ok;
        }

        /// <summary>Begin per-process tracing (all threads, new threads inherit). False on failure.</summary>
        public bool Start(int pid)
        {
            _hProcess = NativeMethods.OpenProcess((NativeMethods.ProcessAccess)0x1FFFFF, false, pid);
            if (_hProcess == IntPtr.Zero) return false;
            _tracing = Request(Input(TypeStartProcessTrace, b =>
            {
                BitConverter.GetBytes((ulong)_hProcess).CopyTo(b, 0x10);
                BitConverter.GetBytes(Options).CopyTo(b, 0x18);
            }), new byte[0x18]);
            return _tracing;
        }

        /// <summary>Snapshot the whole process trace (all threads, each with a per-thread
        /// header). Null on failure. Safe to call repeatedly while tracing.</summary>
        public byte[]? ReadTrace()
        {
            if (!_tracing || _hProcess == IntPtr.Zero) return null;
            void FillSizeTrace(byte[] b) { BitConverter.GetBytes(TraceVersionCurrent).CopyTo(b, 0x10); BitConverter.GetBytes((ulong)_hProcess).CopyTo(b, 0x18); }

            var szOut = new byte[0x18];
            if (!Request(Input(TypeGetProcessTraceSize, FillSizeTrace), szOut)) return null;
            ulong size = BitConverter.ToUInt64(szOut, 8); // IPT_OUTPUT_BUFFER GetTraceSize.TraceSize @ 0x08
            if (size < 16 || size > 512UL * 1024 * 1024) return null;

            var trace = new byte[size];
            bool ok = NativeMethods.DeviceIoControl(_device, IOCTL_IPT_READ_TRACE,
                Input(TypeGetProcessTrace, FillSizeTrace), 0x30, trace, (uint)size, out _, IntPtr.Zero);
            return ok ? trace : null;
        }

        public void Stop()
        {
            if (_tracing && _hProcess != IntPtr.Zero)
                Request(Input(TypeStopProcessTrace, b => BitConverter.GetBytes((ulong)_hProcess).CopyTo(b, 0x10)), null);
            _tracing = false;
        }

        /// <summary>Read up to <c>buf.Length</c> bytes of the traced process's memory at
        /// <paramref name="addr"/> (the trace-read handle has VM_READ). Used by
        /// <see cref="PtDecoder"/> to disassemble the executed code path. 0 on failure.</summary>
        public int ReadMemory(ulong addr, byte[] buf)
        {
            if (_hProcess == IntPtr.Zero) return 0;
            return NativeMethods.ReadProcessMemory(_hProcess, (IntPtr)(long)addr, buf, (IntPtr)buf.Length, out IntPtr read)
                ? (int)(long)read : 0;
        }

        public void Dispose()
        {
            try { Stop(); } catch { /* best effort */ }
            if (_hProcess != IntPtr.Zero) { NativeMethods.CloseHandle(_hProcess); _hProcess = IntPtr.Zero; }
            if (IsOpen) { NativeMethods.CloseHandle(_device); _device = InvalidHandle; }
        }
    }
}
