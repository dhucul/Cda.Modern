using System;
using System.Runtime.InteropServices;
using Cda.Core.Cpu;

namespace Cda.Core.Engine
{
    /// <summary>
    /// In-process validation of the capture stub + ring buffer, paralleling
    /// <see cref="HookSelfTest"/>. It hooks a tiny native function with the
    /// capture stub, calls it a few times, drains the buffer, and checks that one
    /// record per call was recorded with the right destination — and that the
    /// function still returns correctly (proving the trampoline chain).
    ///
    /// It tests whichever stub matches the current process (x86 stub in a 32-bit
    /// build, x64 stub in a 64-bit build), since the stub is native code for that
    /// architecture.
    /// </summary>
    public static class CaptureStubSelfTest
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int IntFunc();

        public static string Run()
        {
            bool is64 = Environment.Is64BitProcess;
            const int argCount = 4;
            int recordSize = CaptureStub.RecordSize(argCount);

            var mem = new LocalCodeMemory();
            var arch = CpuArchitectures.For(is64);

            var buffer = CaptureBuffer.Create(mem, requestedSlots: 256, recordSize: recordSize);

            // Target: mov eax, 0x1234 ; ret  (padded with NOPs).
            ulong func = mem.Allocate(64, executable: true);
            byte[] code = new byte[64];
            code[0] = 0xB8; code[1] = 0x34; code[2] = 0x12; code[3] = 0x00; code[4] = 0x00; code[5] = 0xC3;
            for (int i = 6; i < code.Length; i++) code[i] = 0x90;
            mem.Write(func, code);
            mem.Flush(func, code.Length);

            ulong stub = mem.Allocate(512, executable: true);

            InlineHook hook;
            try { hook = InlineHook.Install(arch, mem, func, stub); }
            catch (Exception ex) { return "FAIL: hook install — " + ex.Message; }

            byte[] stubBytes;
            try
            {
                stubBytes = CaptureStub.Build(is64, stub, func, buffer.ControlAddress,
                    buffer.DataAddress, hook.Trampoline, argCount, buffer.SlotCount);
            }
            catch (Exception ex) { return "FAIL: stub assembly — " + ex.Message; }

            if (stubBytes.Length > 512) return $"FAIL: stub too large ({stubBytes.Length} bytes).";
            mem.Write(stub, stubBytes);
            mem.Flush(stub, stubBytes.Length);

            var fn = Marshal.GetDelegateForFunctionPointer<IntFunc>((IntPtr)unchecked((long)func));
            const int n = 5;
            int lastRet = 0;
            for (int i = 0; i < n; i++) lastRet = fn();
            GC.KeepAlive(fn);

            hook.Remove();

            uint readSeq = 0;
            byte[] data = buffer.DrainSince(mem, ref readSeq, out _);
            var records = RingBufferReader.Decode(data, qpcBase: 0, qpcFrequency: 1.0);

            if (lastRet != 0x1234)
                return $"FAIL: function returned 0x{lastRet:X}, expected 0x1234 (trampoline chain broken).";
            if (records.Count != n)
                return $"FAIL: captured {records.Count} records, expected {n} (buffer/stub write path).";
            foreach (var r in records)
                if (r.Destination != func)
                    return $"FAIL: record destination 0x{r.Destination:X} != 0x{func:X}.";

            return $"PASS ({arch.Name}): captured {records.Count} calls into the ring buffer · " +
                   $"dest=0x{func:X} · {records[0].IntegerArgs.Length} args/record · {recordSize}-byte records.";
        }
    }
}
