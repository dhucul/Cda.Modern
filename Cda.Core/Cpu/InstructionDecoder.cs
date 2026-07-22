using System;
using System.Collections.Generic;
using Iced.Intel;
using Cda.Core.Memory;

namespace Cda.Core.Cpu
{
    /// <summary>
    /// Thin wrapper over the Iced decoder shared by both architectures. This
    /// replaces the legacy hand-rolled length decoder / call scanner. The same
    /// code serves x86 and x64 by passing <c>bitness</c> 32 or 64.
    /// </summary>
    internal static class Disasm
    {
        /// <summary>Enumerate direct near calls (site, absolute target) in a code blob.</summary>
        public static IEnumerable<(ulong Site, ulong Target)> FindDirectCalls(
            int bitness, ReadOnlyMemory<byte> code, ulong codeBase)
        {
            var data = code.ToArray();
            var reader = new ByteArrayCodeReader(data);
            var decoder = Decoder.Create(bitness, reader, codeBase, DecoderOptions.None);

            while (reader.CanReadByte)
            {
                decoder.Decode(out Instruction instr);
                if (instr.Code == Code.INVALID) continue;

                if (instr.FlowControl == FlowControl.Call &&
                    (instr.Op0Kind == OpKind.NearBranch16 ||
                     instr.Op0Kind == OpKind.NearBranch32 ||
                     instr.Op0Kind == OpKind.NearBranch64))
                {
                    ulong target = instr.NearBranchTarget;
                    // `call $+5; pop reg` (or its operand-size variant) obtains
                    // the current instruction pointer; the following instruction
                    // is not a subroutine entry. Promoting it produced phantom
                    // sub_XXXXXXXX rows that no real disassembler recognizes.
                    if (target != instr.NextIP)
                        yield return (instr.IP, target);
                }
            }
        }

        /// <summary>
        /// Direct-call scan that reads code <b>on demand</b> from an
        /// <see cref="IMemorySource"/> (addresses are whatever that source uses — file
        /// offsets for a mapped file, VAs for a live process) instead of materializing
        /// the whole range. Iced pulls bytes through a small fixed window, so a section
        /// of any size — a multi-hundred-MB <c>.text</c> — is decoded with flat
        /// (~64 KB) managed memory and no full-buffer copy. This is what lets discovery
        /// cover an entire large module rather than just its first slice.
        /// </summary>
        /// <param name="start">Address in <paramref name="memory"/>'s space where the code begins.</param>
        /// <param name="length">Number of bytes to decode from <paramref name="start"/>.</param>
        /// <param name="codeBase">Virtual address the first byte maps to (for reported sites/targets).</param>
        public static IEnumerable<(ulong Site, ulong Target)> FindDirectCalls(
            int bitness, IMemorySource memory, ulong start, long length, ulong codeBase)
        {
            if (length <= 0) yield break;

            var reader = new MemorySourceCodeReader(memory, start, length);
            var decoder = Decoder.Create(bitness, reader, codeBase, DecoderOptions.None);
            ulong end = codeBase + (ulong)length;

            while (decoder.IP < end)
            {
                decoder.Decode(out Instruction instr);
                // The streaming reader signals exhaustion (or an unreadable page) by
                // running out of bytes; stop rather than spin on a stalled IP.
                if (decoder.LastError == DecoderError.NoMoreBytes) yield break;
                if (instr.Code == Code.INVALID) continue;

                if (instr.FlowControl == FlowControl.Call &&
                    (instr.Op0Kind == OpKind.NearBranch16 ||
                     instr.Op0Kind == OpKind.NearBranch32 ||
                     instr.Op0Kind == OpKind.NearBranch64))
                {
                    ulong target = instr.NearBranchTarget;
                    if (target != instr.NextIP)
                        yield return (instr.IP, target);
                }
            }
        }

        /// <summary>
        /// An Iced <see cref="CodeReader"/> that feeds the decoder from an
        /// <see cref="IMemorySource"/> a window at a time, so an arbitrarily large code
        /// region is decoded sequentially without ever copying it into one buffer.
        /// </summary>
        private sealed class MemorySourceCodeReader : CodeReader
        {
            private readonly IMemorySource _mem;
            private readonly ulong _start;
            private readonly long _length;
            private readonly byte[] _buf = new byte[0x10000];
            private long _pos;   // bytes consumed from [start, start+length)
            private int _bufOff; // read cursor within _buf
            private int _bufLen; // valid bytes in _buf

            public MemorySourceCodeReader(IMemorySource mem, ulong start, long length)
            {
                _mem = mem;
                _start = start;
                _length = length;
            }

            public override int ReadByte()
            {
                if (_bufOff >= _bufLen)
                {
                    if (_pos >= _length) return -1;
                    int want = (int)Math.Min(_buf.Length, _length - _pos);
                    int read = _mem.ReadMemory(_start + (ulong)_pos, _buf.AsSpan(0, want));
                    if (read <= 0) return -1; // exhausted or an unreadable page
                    _bufLen = read;
                    _bufOff = 0;
                    _pos += read;
                }
                return _buf[_bufOff++];
            }
        }

        /// <summary>
        /// Number of whole-instruction bytes at <paramref name="address"/> that
        /// must be relocated so a detour of at least <paramref name="minBytes"/>
        /// can be written without splitting an instruction.
        /// </summary>
        public static int HookLength(int bitness, IMemorySource memory, ulong address, int minBytes)
        {
            byte[] buf = new byte[Math.Max(minBytes + 16, 32)];
            int read = memory.ReadMemory(address, buf);
            if (read <= 0) return 0;

            var reader = new ByteArrayCodeReader(buf, 0, read);
            var decoder = Decoder.Create(bitness, reader, address, DecoderOptions.None);

            int total = 0;
            while (total < minBytes && reader.CanReadByte)
            {
                decoder.Decode(out Instruction instr);
                if (instr.Code == Code.INVALID) return 0; // refuse to hook unknown code
                total += instr.Length;
                if (total < minBytes && EndsFunction(instr))
                    return 0; // function ends before we have room — too short to hook safely
            }
            return total >= minBytes ? total : 0;
        }

        /// <summary>
        /// Whole-instruction byte count at the start of <paramref name="code"/>
        /// that must be relocated for a detour of at least <paramref name="minBytes"/>.
        /// Returns 0 if an instruction can't be decoded.
        /// </summary>
        public static int HookLengthBytes(int bitness, byte[] code, int minBytes)
        {
            var reader = new ByteArrayCodeReader(code);
            var decoder = Decoder.Create(bitness, reader, 0x1000, DecoderOptions.None);
            int total = 0;
            while (total < minBytes && reader.CanReadByte)
            {
                decoder.Decode(out Instruction instr);
                if (instr.Code == Code.INVALID) return 0;
                total += instr.Length;
                if (total < minBytes && EndsFunction(instr))
                    return 0; // function ends before we have room — too short to hook safely
            }
            return total >= minBytes ? total : 0;
        }

        // A function boundary: stealing past any of these would corrupt whatever
        // follows (often the next function or int3/nop padding).
        private static bool EndsFunction(in Instruction instr) =>
            instr.FlowControl == FlowControl.Return ||
            instr.FlowControl == FlowControl.UnconditionalBranch ||
            instr.Code == Code.Int3;

        /// <summary>Decode a run of instructions for relocation by the block encoder.</summary>
        public static List<Instruction> DecodeRange(int bitness, byte[] code, ulong ip, int byteCount)
        {
            var reader = new ByteArrayCodeReader(code, 0, Math.Min(byteCount, code.Length));
            var decoder = Decoder.Create(bitness, reader, ip, DecoderOptions.None);
            var list = new List<Instruction>();
            int consumed = 0;
            while (consumed < byteCount && reader.CanReadByte)
            {
                decoder.Decode(out Instruction instr);
                if (instr.Code == Code.INVALID) break;
                list.Add(instr);
                consumed += instr.Length;
            }
            return list;
        }

        /// <summary>
        /// Decode and MASM-format a bounded run of instructions for display (the
        /// Disassembly view). Bytes are read from <paramref name="memory"/> at
        /// <paramref name="readStart"/> (a file offset for a mapped image, a VA for a
        /// live process), while instruction addresses/branch targets are reported
        /// against <paramref name="ipBase"/> (the function's virtual address) — the
        /// same read-at-offset / decode-as-VA split the discovery scan uses. Decoding
        /// stops at <paramref name="maxBytes"/> or the first function boundary
        /// (<see cref="EndsFunction"/>), since a discovered function carries no size.
        /// </summary>
        public static List<DisasmLine> DecodeFormatted(
            int bitness, IMemorySource memory, ulong readStart, ulong ipBase, int maxBytes)
        {
            var lines = new List<DisasmLine>();
            if (maxBytes <= 0) return lines;

            byte[] buf = new byte[maxBytes];
            int read = memory.ReadMemory(readStart, buf);
            if (read <= 0) return lines;

            var reader = new ByteArrayCodeReader(buf, 0, read);
            var decoder = Decoder.Create(bitness, reader, ipBase, DecoderOptions.None);
            var formatter = new MasmFormatter();
            var output = new StringOutput();

            int consumed = 0;
            while (consumed < read)
            {
                decoder.Decode(out Instruction instr);
                if (instr.Code == Code.INVALID) break;
                int len = instr.Length;
                if (len <= 0 || consumed + len > read) break;

                var bytes = new byte[len];
                Array.Copy(buf, consumed, bytes, 0, len);

                formatter.Format(instr, output);
                lines.Add(new DisasmLine(instr.IP, bytes, output.ToStringAndReset()));

                consumed += len;
                if (EndsFunction(instr)) break; // ret / uncond-jmp / int3 — end of function
            }
            return lines;
        }
    }

    /// <summary>One decoded, formatted instruction line for the Disassembly view.</summary>
    public readonly struct DisasmLine
    {
        /// <summary>Virtual address of the instruction.</summary>
        public readonly ulong Address;
        /// <summary>Raw instruction bytes.</summary>
        public readonly byte[] Bytes;
        /// <summary>MASM-formatted mnemonic + operands.</summary>
        public readonly string Text;

        public DisasmLine(ulong address, byte[] bytes, string text)
        {
            Address = address;
            Bytes = bytes;
            Text = text;
        }
    }

    /// <summary>A <see cref="CodeWriter"/> that accumulates encoded bytes.</summary>
    internal sealed class ListCodeWriter : CodeWriter
    {
        public readonly List<byte> Bytes = new();
        public override void WriteByte(byte value) => Bytes.Add(value);
    }
}
