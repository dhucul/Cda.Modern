using System;
using System.Buffers.Binary;
using System.Text;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Extracts the <b>caption</b> (title bar text) from a Win32 dialog-box template —
    /// the <c>DLGTEMPLATE</c> or <c>DLGTEMPLATEEX</c> blob that a resource-defined dialog
    /// (<c>DialogBoxParam</c> / <c>CreateDialogParam</c> and their <c>*IndirectParam</c>
    /// forms) is built from.
    ///
    /// Why this is needed: a <c>MessageBox</c> passes its text and caption as string
    /// <i>arguments</i>, so the host-side pointer-following that decodes call arguments
    /// (<see cref="CaptureSession"/> dereference enrichment) recovers them. A custom app
    /// dialog's caption is not an argument at all — it lives INSIDE the template — so it
    /// can only be recovered by parsing the template itself. The caller supplies the
    /// template bytes (read from the module's resource section for the <c>*Param</c> forms,
    /// or straight from target memory for the in-memory <c>*IndirectParam</c> forms).
    ///
    /// Template layout (little-endian). A standard <c>DLGTEMPLATE</c> begins with
    /// <c>DWORD style</c>; an extended <c>DLGTEMPLATEEX</c> begins with
    /// <c>WORD dlgVer</c> then <c>WORD signature == 0xFFFF</c> — that signature word (at
    /// offset 2) is how the two are told apart, exactly as the loader does it. After the
    /// fixed header come three variable-length fields in order: <b>menu</b>,
    /// <b>windowClass</b> (each a "sz_Or_Ord": absent / ordinal / string), then the
    /// <b>title</b> — a NUL-terminated wide string, which is the caption.
    /// </summary>
    public static class DialogTemplate
    {
        /// <summary>
        /// Parse a dialog template and return its caption, or null if the template has no
        /// caption or is too short/malformed to read one. Only the leading header + the
        /// menu/class/title fields are read, so a partial (head-only) template is fine.
        /// </summary>
        public static string? ReadCaption(ReadOnlySpan<byte> t)
        {
            if (t.Length < 4) return null;

            // DLGTEMPLATEEX iff the signature word (offset 2) is 0xFFFF (dlgVer is offset 0).
            ushort signature = BinaryPrimitives.ReadUInt16LittleEndian(t.Slice(2));
            bool ex = signature == 0xFFFF;

            // Fixed header size up to the variable fields:
            //   DLGTEMPLATE   : style(4) exStyle(4) cdit(2) x(2) y(2) cx(2) cy(2)          = 18
            //   DLGTEMPLATEEX : dlgVer(2) sig(2) helpID(4) exStyle(4) style(4) cDlgItems(2)
            //                   x(2) y(2) cx(2) cy(2)                                       = 26
            int pos = ex ? 26 : 18;

            pos = SkipSzOrOrd(t, pos);   // menu
            pos = SkipSzOrOrd(t, pos);   // windowClass
            if (pos < 0) return null;
            return ReadTitle(t, pos);    // caption
        }

        // Advance past a "sz_Or_Ord" field: a single 0x0000 word means "none"; a leading
        // 0xFFFF word means an ordinal (0xFFFF followed by one id word); otherwise it is a
        // NUL-terminated wide string. Returns the new position, or -1 if it runs off the end.
        private static int SkipSzOrOrd(ReadOnlySpan<byte> t, int pos)
        {
            if (pos < 0 || pos + 2 > t.Length) return -1;
            ushort first = BinaryPrimitives.ReadUInt16LittleEndian(t.Slice(pos));
            if (first == 0x0000) return pos + 2;   // absent
            if (first == 0xFFFF) return pos + 4;   // ordinal: 0xFFFF + one id word
            // NUL-terminated wide string.
            while (pos + 2 <= t.Length)
            {
                ushort c = BinaryPrimitives.ReadUInt16LittleEndian(t.Slice(pos));
                pos += 2;
                if (c == 0) return pos;
            }
            return -1;
        }

        // The title field is always a NUL-terminated wide string (never an ordinal); a
        // leading 0x0000 word means an empty caption. Returns null when empty.
        private static string? ReadTitle(ReadOnlySpan<byte> t, int pos)
        {
            var sb = new StringBuilder();
            bool terminated = false;
            while (pos + 2 <= t.Length)
            {
                ushort c = BinaryPrimitives.ReadUInt16LittleEndian(t.Slice(pos));
                pos += 2;
                if (c == 0) { terminated = true; break; }
                sb.Append((char)c);
            }
            return terminated && sb.Length > 0 ? sb.ToString() : null;
        }
    }
}
