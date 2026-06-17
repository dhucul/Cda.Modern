using System;

namespace Cda.Core.Model
{
    public enum DereferenceKind : byte
    {
        Raw = 0,
        AnsiString = 1,
        WideString = 2,
        Pointer = 3,
    }

    /// <summary>
    /// Modern replacement for the legacy <c>dereference</c> type. When an
    /// argument looks like a pointer, the engine follows it and snapshots the
    /// pointed-to bytes (or decodes a string). <see cref="ArgumentIndex"/> ties
    /// the capture back to the argument it came from.
    /// </summary>
    public sealed class Dereference
    {
        public int ArgumentIndex;
        public DereferenceKind Kind;
        public ulong Pointer;
        public byte[] Data = Array.Empty<byte>();

        public bool IsString =>
            Kind == DereferenceKind.AnsiString || Kind == DereferenceKind.WideString;

        public string? AsString()
        {
            if (Data.Length == 0) return null;
            string? s = Kind switch
            {
                DereferenceKind.AnsiString => System.Text.Encoding.ASCII.GetString(Data),
                DereferenceKind.WideString => System.Text.Encoding.Unicode.GetString(Data),
                _ => null
            };
            if (s == null) return null;

            // Collapse control characters (the embedded tab/newline/CR a decoded
            // string may now contain, plus any stray NUL) to spaces so the value
            // stays on one line in the call log; the raw bytes remain in Data.
            char[] chars = s.ToCharArray();
            for (int i = 0; i < chars.Length; i++)
                if (chars[i] < ' ' || chars[i] == (char)0x7F) chars[i] = ' ';
            return new string(chars).TrimEnd();
        }
    }
}
