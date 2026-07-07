using System;
using System.Runtime.InteropServices;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Validates the x64 return-capture vectored exception handler's fixup logic
    /// in-process (the delicate part), WITHOUT needing a real exception: set up several
    /// return contexts + a fake <c>EXCEPTION_POINTERS</c>/<c>CONTEXT</c>, invoke the
    /// handler as a function, and check it restores the in-range redirected return slot
    /// (and releases it) while leaving the below-range and above-range ones untouched.
    /// This exercises the exact bytes <see cref="CaptureStub.BuildReturnVehX64"/>
    /// emits — offsets into EXCEPTION_POINTERS/CONTEXT, the registry loop, the range
    /// check, and the restore. x64 only (x86 uses chain-based SEH, which return-address
    /// redirection does not disturb, so no handler is installed there).
    /// </summary>
    public static class CaptureVehSelfTest
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int VehFunc(IntPtr exceptionPointers);

        private const int ContextRspOffset = 0x98; // CONTEXT.Rsp on x64

        public static string Run()
        {
            if (!Environment.Is64BitProcess)
                return "SKIP (x86: return-address redirection doesn't disturb chain-based SEH; no handler needed).";

            var mem = new LocalCodeMemory();
            int scan = 0x800000; // 8 MB, matches production

            // Real return slot for the in-range context, seeded with a stand-in for the
            // return-stub address (what the entry stub would have written there).
            const ulong redirected = 0x1111_2222_3333_4444;
            const ulong origA = 0xAAAA_BBBB_CCCC_DDDD;
            ulong slotA = mem.Allocate(8, executable: false);
            WriteU64(mem, slotA, redirected);

            ulong faultRsp = slotA - 0x100;         // slotA is 0x100 above the fault → in range
            ulong belowSlot = faultRsp - 0x100000;  // below the fault → must be skipped (never written)
            ulong aboveSlot = faultRsp + (ulong)scan + 0x1000; // beyond the scan → must be skipped

            // Three contexts, all busy: A in range, B below, C above.
            ulong ctxA = MakeCtx(mem, origA, slotA);
            ulong ctxB = MakeCtx(mem, 0xB0, belowSlot);
            ulong ctxC = MakeCtx(mem, 0xC0, aboveSlot);

            // Registry: u64 count, then the ctx addresses.
            ulong registry = mem.Allocate(8 + 3 * 8, executable: false);
            WriteU64(mem, registry, 3);
            WriteU64(mem, registry + 8, ctxA);
            WriteU64(mem, registry + 16, ctxB);
            WriteU64(mem, registry + 24, ctxC);

            ulong veh = mem.Allocate(512, executable: true);
            byte[] vehBytes = CaptureStub.BuildReturnVehX64(veh, registry, scan);
            if (vehBytes.Length > 512) return $"FAIL: VEH too large ({vehBytes.Length} bytes).";
            mem.Write(veh, vehBytes); mem.Flush(veh, vehBytes.Length);

            // Fake CONTEXT (only Rsp matters) + EXCEPTION_POINTERS { ExceptionRecord, ContextRecord }.
            ulong context = mem.Allocate(0x600, executable: false);
            WriteU64(mem, context + ContextRspOffset, faultRsp);
            ulong excPtrs = mem.Allocate(16, executable: false);
            WriteU64(mem, excPtrs, 0);          // ExceptionRecord (unused)
            WriteU64(mem, excPtrs + 8, context); // ContextRecord

            var fn = Marshal.GetDelegateForFunctionPointer<VehFunc>((IntPtr)unchecked((long)veh));
            int rc = fn((IntPtr)unchecked((long)excPtrs));
            GC.KeepAlive(fn);

            if (rc != 0)
                return $"FAIL: handler returned {rc}, expected 0 (EXCEPTION_CONTINUE_SEARCH).";
            if (ReadU64(mem, slotA) != origA)
                return $"FAIL: in-range slot not restored (0x{ReadU64(mem, slotA):X}, expected 0x{origA:X}).";
            if (ReadU32(mem, ctxA + (uint)CaptureStub.CtxBusy) != 0)
                return "FAIL: in-range context not released (busy still set).";
            if (ReadU32(mem, ctxB + (uint)CaptureStub.CtxBusy) != 1)
                return "FAIL: below-range context was wrongly touched.";
            if (ReadU32(mem, ctxC + (uint)CaptureStub.CtxBusy) != 1)
                return "FAIL: above-range context was wrongly touched.";

            return "PASS (x64): VEH restored the in-range redirected return, released it, and skipped out-of-range slots.";
        }

        private static ulong MakeCtx(LocalCodeMemory mem, ulong origRet, ulong slotAddr)
        {
            ulong ctx = mem.Allocate(CaptureStub.ReturnContextSize, executable: false);
            WriteU32(mem, ctx + (uint)CaptureStub.CtxBusy, 1);
            WriteU64(mem, ctx + (uint)CaptureStub.CtxOrigRet, origRet);
            WriteU64(mem, ctx + (uint)CaptureStub.CtxSlotAddr, slotAddr);
            return ctx;
        }

        private static void WriteU64(LocalCodeMemory mem, ulong addr, ulong v) => mem.Write(addr, BitConverter.GetBytes(v));
        private static void WriteU32(LocalCodeMemory mem, ulong addr, uint v) => mem.Write(addr, BitConverter.GetBytes(v));

        private static ulong ReadU64(LocalCodeMemory mem, ulong addr)
        {
            byte[] b = new byte[8]; mem.Read(addr, b); return BitConverter.ToUInt64(b, 0);
        }
        private static uint ReadU32(LocalCodeMemory mem, ulong addr)
        {
            byte[] b = new byte[4]; mem.Read(addr, b); return BitConverter.ToUInt32(b, 0);
        }
    }
}
