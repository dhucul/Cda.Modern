using System;
using System.Collections.Generic;
using System.IO;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Deterministic in-process check of <see cref="PtDecoder"/>'s control-flow reconstruction.
    /// Assembles a real <c>cmp/je/cmp/ja/…/call</c> blob (the dlgtest shape) and a matching
    /// synthetic PT stream (PSB sync, TIP.PGE to the entry, two not-taken TNT bits, a TIP to
    /// the dialog API), then asserts the decoder walks the instructions, attributes each TNT
    /// bit to the right branch by ADDRESS, and confirms the `ja` skip-over that fell through —
    /// and that a candidate branch NOT on the executed path is never confirmed. No Intel
    /// hardware or the IPT driver required.
    /// </summary>
    public static class PtDecoderSelfTest
    {
        public static string Run()
        {
            const ulong Base = 0x140010000UL;
            const ulong dialogApi = 0x00007FFF_44ABED80UL;

            // Assemble: cmp ecx,7 ; je box ; cmp edx,4 ; ja skip ; box: xor eax,eax ; call rax ; skip: ret
            var asm = new Assembler(64);
            var box = asm.CreateLabel();
            var skip = asm.CreateLabel();
            asm.cmp(ecx, 7);
            asm.je(box);
            asm.cmp(edx, 4);
            asm.ja(skip);
            asm.Label(ref box);
            asm.xor(eax, eax);
            asm.call(rax);            // indirect call → consumes a TIP (= dialogApi)
            asm.Label(ref skip);
            asm.ret();
            var ms = new MemoryStream();
            asm.Assemble(new StreamCodeWriter(ms), Base);
            byte[] code = ms.ToArray();

            // Find the je / ja addresses in the assembled blob.
            ulong jeAddr = 0, jaAddr = 0;
            var d = Decoder.Create(64, new ByteArrayCodeReader(code), Base, DecoderOptions.None);
            while (d.IP < Base + (ulong)code.Length)
            {
                d.Decode(out var ins);
                if (ins.Code == Code.INVALID) break;
                if (ins.Code == Code.Je_rel8_64) jeAddr = ins.IP;
                else if (ins.Code == Code.Ja_rel8_64) jaAddr = ins.IP;
            }
            if (jeAddr == 0 || jaAddr == 0) return "FAIL: couldn't locate je/ja in the assembled blob.";

            int ReadCode(ulong addr, byte[] buf)
            {
                if (addr < Base || addr >= Base + (ulong)code.Length) return 0;
                int off = (int)(addr - Base), n = Math.Min(buf.Length, code.Length - off);
                Array.Copy(code, off, buf, 0, n);
                return n;
            }

            // show(3,2): je NOT taken (a!=7), ja NOT taken (x<=4) → both fall through to the box.
            byte[] trace = BuildTrace(Base, dialogApi, jeTaken: false, jaTaken: false);

            var candidates = new List<DialogBranchConfirmer.Candidate>
            {
                new(jaAddr, Code.Ja_rel8_64, BranchRole.SkipOver,  "ja short 00000140000100A9h"),  // nearest
                new(jeAddr, Code.Je_rel8_64, BranchRole.EntryGate, "je short 0000014000010090h"),
            };

            var conf = PtDecoder.TryConfirm(trace, dialogApi, Base + 0x100, candidates, is64: true, ReadCode);
            if (conf == null) return "FAIL: reconstruction found no dialog call.";
            if (conf.BranchAddress != jaAddr) return $"FAIL: confirmed 0x{conf.BranchAddress:X}, expected the ja 0x{jaAddr:X}.";
            if (!conf.Text.Contains("ja") || !conf.Text.Contains("(not taken)")) return "FAIL: text malformed: " + conf.Text;

            // A candidate NOT on the trace's executed path (a bogus address) must never be
            // confirmed AS ITSELF. Instead the ground-truth fallback reconstructs the real
            // executed gate (the ja) — so a wrong static guess can't produce a false branch,
            // and the true gate is still surfaced.
            var bogus = new List<DialogBranchConfirmer.Candidate>
            {
                new(Base + 0x777, Code.Jne_rel8_64, BranchRole.EntryGate, "jne short deadh"),
            };
            var b2 = PtDecoder.TryConfirm(trace, dialogApi, Base + 0x100, bogus, is64: true, ReadCode);
            if (b2 != null && b2.BranchAddress == Base + 0x777) return "FAIL: confirmed a candidate that never executed.";
            if (b2 == null || b2.BranchAddress != jaAddr) return "FAIL: ground-truth fallback didn't recover the real executed gate.";

            return "PASS: PT control-flow reconstruction (walk je/ja by address → ja not-taken; bogus candidate rejected, real gate recovered by ground truth).";
        }

        // One thread's PT stream: PSB, PSBEND, TIP.PGE(entry), a short TNT with the je/ja bits,
        // then a TIP to the dialog API (the indirect call's target). Wrapped in the trace framing.
        private static byte[] BuildTrace(ulong entry, ulong dialogApi, bool jeTaken, bool jaTaken)
        {
            var pt = new List<byte>();
            for (int i = 0; i < 8; i++) { pt.Add(0x02); pt.Add(0x82); } // PSB (16 bytes)
            pt.Add(0x02); pt.Add(0x23);                                 // PSBEND
            pt.Add(0xD1); pt.AddRange(BitConverter.GetBytes(entry));    // TIP.PGE, full IP → entry
            pt.Add(ShortTnt(jeTaken, jaTaken));                         // 2 TNT bits, execution order je,ja
            pt.Add(0xCD); pt.AddRange(BitConverter.GetBytes(dialogApi));// TIP, full IP → dialog API (call rax target)
            byte[] stream = pt.ToArray();

            var buf = new List<byte>();
            buf.AddRange(BitConverter.GetBytes((ushort)1)); // IPT_TRACE_DATA.TraceVersion
            buf.AddRange(BitConverter.GetBytes((ushort)1)); // ValidTrace
            buf.AddRange(BitConverter.GetBytes((uint)0));   // TraceSize (unused by the decoder)
            buf.AddRange(BitConverter.GetBytes((ulong)4242)); // ThreadId
            buf.AddRange(BitConverter.GetBytes((uint)0));   // Timing
            buf.AddRange(BitConverter.GetBytes((uint)0));   // Mtc
            buf.AddRange(BitConverter.GetBytes((uint)0));   // FreqRatio
            buf.AddRange(BitConverter.GetBytes((uint)0));   // RingBufferOffset
            buf.AddRange(BitConverter.GetBytes((uint)stream.Length)); // TraceSize
            buf.AddRange(stream);
            return buf.ToArray();
        }

        private static byte ShortTnt(bool b0, bool b1)
        {
            int payload = 0b100 | (b0 ? 0b10 : 0) | (b1 ? 0b01 : 0); // stop@bit2, je@bit1, ja@bit0
            return (byte)(payload << 1);
        }
    }
}
