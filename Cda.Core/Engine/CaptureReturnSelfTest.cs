using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Cda.Core.Cpu;
using Cda.Core.Model;

namespace Cda.Core.Engine
{
    /// <summary>
    /// In-process validation of return-value capture, paralleling
    /// <see cref="CaptureStubSelfTest"/>. It hooks a tiny native function whose
    /// return value is known (<c>mov eax,0x1234 ; ret</c>) with return capture
    /// enabled, calls it a few times, drains, and checks that:
    ///   * the function still returns 0x1234 (the redirect + resume is transparent),
    ///   * one call record and one paired return record were captured per call,
    ///   * the return record carries the return value 0x1234, and
    ///   * the return record's correlation id matches its call.
    /// It exercises whichever stub matches the current process (x64 in a 64-bit
    /// build, x86 in a 32-bit build).
    /// </summary>
    public static class CaptureReturnSelfTest
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

            ulong ctx = mem.Allocate(CaptureStub.ReturnContextSize, executable: false); // zero-init: busy = 0
            ulong retStub = mem.Allocate(512, executable: true);
            ulong stub = mem.Allocate(512, executable: true);

            InlineHook hook;
            try { hook = InlineHook.Install(arch, mem, func, stub); }
            catch (Exception ex) { return "FAIL: hook install — " + ex.Message; }

            byte[] retStubBytes, stubBytes;
            try
            {
                retStubBytes = CaptureStub.BuildReturnStub(is64, retStub, func, buffer.ControlAddress,
                    buffer.DataAddress, argCount, buffer.SlotCount, ctx);
                stubBytes = CaptureStub.Build(is64, stub, func, buffer.ControlAddress,
                    buffer.DataAddress, hook.Trampoline, argCount, buffer.SlotCount,
                    returnStubAddress: retStub, returnCtxAddress: ctx);
            }
            catch (Exception ex) { return "FAIL: stub assembly — " + ex.Message; }

            if (retStubBytes.Length > 512) return $"FAIL: return stub too large ({retStubBytes.Length} bytes).";
            if (stubBytes.Length > 512) return $"FAIL: stub too large ({stubBytes.Length} bytes).";
            mem.Write(retStub, retStubBytes); mem.Flush(retStub, retStubBytes.Length);
            mem.Write(stub, stubBytes); mem.Flush(stub, stubBytes.Length);

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
                return $"FAIL: function returned 0x{lastRet:X}, expected 0x1234 (return redirect/resume broken).";

            var calls = new List<CallRecord>();
            var returns = new List<CallRecord>();
            foreach (var r in records) (r.IsReturn ? returns : calls).Add(r);

            if (calls.Count != n)
                return $"FAIL: captured {calls.Count} call records, expected {n}.";
            if (returns.Count != n)
                return $"FAIL: captured {returns.Count} return records, expected {n}.";

            // Pair by correlation id and check the return value.
            var byCorr = new Dictionary<uint, CallRecord>();
            foreach (var c in calls) byCorr[c.CorrelationId] = c;
            foreach (var ret in returns)
            {
                if (!byCorr.ContainsKey(ret.CorrelationId))
                    return $"FAIL: return corrId {ret.CorrelationId} has no matching call.";
                if (ret.Destination != func)
                    return $"FAIL: return destination 0x{ret.Destination:X} != 0x{func:X}.";
                if (ret.IntegerArgs.Length < 1 || ret.IntegerArgs[0] != 0x1234)
                    return $"FAIL: return value 0x{(ret.IntegerArgs.Length > 0 ? ret.IntegerArgs[0] : 0):X}, expected 0x1234.";
            }

            return $"PASS ({arch.Name}): {n} calls, {n} returns paired · return value 0x1234 · " +
                   $"{recordSize}-byte records.";
        }
    }
}
