using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace Cda.Core.Pe
{
    public enum PeMachine : ushort
    {
        Unknown = 0,
        I386 = 0x014C,
        Amd64 = 0x8664,
        Arm64 = 0xAA64,
    }

    public sealed class PeExport
    {
        public uint Rva;             // function RVA (0 if forwarder)
        public ushort Ordinal;
        public string? Name;         // null for export-by-ordinal-only
        public string? ForwarderTo;  // set when the export forwards to another DLL
        public bool IsForwarder => ForwarderTo != null;
    }

    public sealed class PeImport
    {
        public string ModuleName = "";
        public string? Name;     // null when imported by ordinal
        public ushort Ordinal;
        public uint IatRva;      // slot in the Import Address Table
        public bool ByOrdinal => Name == null;
    }

    public sealed class PeSection
    {
        public string Name = "";
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint RawSize;
        public uint RawPointer;
        public uint Characteristics;
    }

    /// <summary>
    /// A managed PE/COFF reader supporting both PE32 (0x10B) and PE32+ (0x20B),
    /// over either an on-disk file image or a memory-mapped (loaded) image. This
    /// replaces the legacy hand-rolled header structs and the export/import
    /// walkers in <c>Function_Debugger.Classes</c>, widened for 64-bit targets.
    ///
    /// All addresses returned to callers are absolute (ImageBase + RVA) when
    /// <see cref="ActualBase"/> is supplied, otherwise RVAs.
    /// </summary>
    public sealed class PeImage
    {
        private readonly byte[] _data;
        private readonly bool _mapped;       // true: RVA == file offset (loaded image)

        public bool Is64Bit { get; private set; }
        public PeMachine Machine { get; private set; }
        public ulong PreferredImageBase { get; private set; }
        public ulong ActualBase { get; private set; }   // base where the image actually lives
        public uint EntryPointRva { get; private set; }
        public uint SizeOfImage { get; private set; }

        public IReadOnlyList<PeSection> Sections => _sections;
        private readonly List<PeSection> _sections = new();

        // Data directory entries [rva, size], indexed by DataDirectory enum.
        private readonly (uint Rva, uint Size)[] _dirs = new (uint, uint)[16];

        private int _optionalHeaderOffset;

        public enum DataDirectory { Export = 0, Import = 1, Resource = 2, Exception = 3, BaseReloc = 5, Debug = 6, Iat = 12 }

        private PeImage(byte[] data, bool mapped, ulong actualBase)
        {
            _data = data;
            _mapped = mapped;
            ActualBase = actualBase;
        }

        public static PeImage FromFile(byte[] fileBytes)
        {
            var img = new PeImage(fileBytes, mapped: false, actualBase: 0);
            img.Parse();
            img.ActualBase = img.PreferredImageBase;
            return img;
        }

        /// <summary>Parse an image already mapped into memory at <paramref name="baseAddress"/>.</summary>
        public static PeImage FromMappedImage(byte[] mappedBytes, ulong baseAddress)
        {
            var img = new PeImage(mappedBytes, mapped: true, actualBase: baseAddress);
            img.Parse();
            return img;
        }

        // IMAGE_DLLCHARACTERISTICS_* ASLR opt-in flags (live in DllCharacteristics).
        public const ushort DllCharacteristicsHighEntropyVa = 0x0020;
        public const ushort DllCharacteristicsDynamicBase = 0x0040;

        /// <summary>The image's DllCharacteristics flags (the ASLR/DEP/CFG opt-ins).</summary>
        public ushort DllCharacteristics => U16(_optionalHeaderOffset + 0x46);

        /// <summary>
        /// Clear the ASLR opt-in bits (DYNAMIC_BASE + HIGH_ENTROPY_VA) directly in a
        /// raw PE <i>file</i> image — the equivalent of linking <c>/DYNAMICBASE:NO</c> —
        /// so the loader maps it at its preferred ImageBase (no entropy) every run,
        /// giving reproducible module bases. Edits <paramref name="fileImage"/> in
        /// place and returns true iff it parsed and at least one bit was actually
        /// cleared (false if it's already non-ASLR, or not a PE). For the preferred
        /// base to actually be honored, system-wide mandatory ASLR (force-relocate)
        /// must be off. DllCharacteristics sits at the same optional-header offset
        /// (0x46) in both PE32 and PE32+.
        /// </summary>
        public static bool TryStripAslr(byte[] fileImage)
        {
            PeImage pe;
            try { pe = FromFile(fileImage); }
            catch { return false; }
            int off = pe._optionalHeaderOffset + 0x46;
            if (off + 2 > fileImage.Length) return false;
            ushort cur = BinaryPrimitives.ReadUInt16LittleEndian(fileImage.AsSpan(off));
            ushort stripped = (ushort)(cur & ~(DllCharacteristicsDynamicBase | DllCharacteristicsHighEntropyVa));
            if (stripped == cur) return false;
            BinaryPrimitives.WriteUInt16LittleEndian(fileImage.AsSpan(off), stripped);
            return true;
        }

        public ulong RvaToVa(uint rva) => ActualBase + rva;

        /// <summary>
        /// The raw [RVA, size] of a data directory entry (e.g. Export, Import,
        /// Exception/.pdata). Returns (0, 0) when the image has no such directory.
        /// </summary>
        public (uint Rva, uint Size) GetDirectory(DataDirectory dir)
        {
            int i = (int)dir;
            return (uint)i < (uint)_dirs.Length ? _dirs[i] : (0u, 0u);
        }

        /// <summary>
        /// Convert an absolute VA to a file offset, for navigating a file-backed
        /// view to a function. Returns false if the VA is outside the image or
        /// falls in a region with no raw backing.
        /// </summary>
        public bool TryVaToFileOffset(ulong va, out uint offset)
        {
            offset = 0;
            if (va < ActualBase) return false;
            int o = RvaToOffset((uint)(va - ActualBase));
            if (o < 0) return false;
            offset = (uint)o;
            return true;
        }

        private int RvaToOffset(uint rva)
        {
            if (_mapped) return (int)rva;
            foreach (var s in _sections)
            {
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.RawSize))
                    return (int)(rva - s.VirtualAddress + s.RawPointer);
            }
            // Headers region (rva below first section) maps 1:1 in the file too.
            if (rva < (_sections.Count > 0 ? _sections[0].VirtualAddress : SizeOfImage))
                return (int)rva;
            return -1;
        }

        private ushort U16(int off) => BinaryPrimitives.ReadUInt16LittleEndian(_data.AsSpan(off));
        private uint U32(int off) => BinaryPrimitives.ReadUInt32LittleEndian(_data.AsSpan(off));
        private ulong U64(int off) => BinaryPrimitives.ReadUInt64LittleEndian(_data.AsSpan(off));

        private void Parse()
        {
            if (_data.Length < 0x40 || U16(0) != 0x5A4D) // 'MZ'
                throw new BadImageFormatException("Not a DOS/PE image (missing MZ).");

            int peOff = (int)U32(0x3C);
            if (peOff <= 0 || peOff + 24 > _data.Length || U32(peOff) != 0x00004550) // 'PE\0\0'
                throw new BadImageFormatException("Missing PE signature.");

            int coff = peOff + 4;
            Machine = (PeMachine)U16(coff);
            ushort numSections = U16(coff + 2);
            ushort optSize = U16(coff + 16);
            _optionalHeaderOffset = coff + 20;

            ushort magic = U16(_optionalHeaderOffset);
            Is64Bit = magic == 0x20B;
            if (magic != 0x10B && magic != 0x20B)
                throw new BadImageFormatException($"Unknown optional header magic 0x{magic:X}.");

            EntryPointRva = U32(_optionalHeaderOffset + 16);

            int dirCountOffset;
            if (Is64Bit)
            {
                PreferredImageBase = U64(_optionalHeaderOffset + 24);
                SizeOfImage = U32(_optionalHeaderOffset + 56);
                dirCountOffset = _optionalHeaderOffset + 108;
            }
            else
            {
                PreferredImageBase = U32(_optionalHeaderOffset + 28);
                SizeOfImage = U32(_optionalHeaderOffset + 56);
                dirCountOffset = _optionalHeaderOffset + 92;
            }

            uint numDirs = U32(dirCountOffset);
            int dirOff = dirCountOffset + 4;
            for (int i = 0; i < 16 && i < numDirs; i++)
            {
                _dirs[i] = (U32(dirOff + i * 8), U32(dirOff + i * 8 + 4));
            }

            int secOff = _optionalHeaderOffset + optSize;
            for (int i = 0; i < numSections; i++)
            {
                int o = secOff + i * 40;
                if (o + 40 > _data.Length) break;
                var s = new PeSection
                {
                    Name = ReadFixedAscii(o, 8),
                    VirtualSize = U32(o + 8),
                    VirtualAddress = U32(o + 12),
                    RawSize = U32(o + 16),
                    RawPointer = U32(o + 20),
                    Characteristics = U32(o + 36),
                };
                _sections.Add(s);
            }
        }

        private string ReadFixedAscii(int off, int len)
        {
            int end = off;
            while (end < off + len && end < _data.Length && _data[end] != 0) end++;
            return Encoding.ASCII.GetString(_data, off, end - off);
        }

        private string ReadCString(uint rva, int max = 512)
        {
            int o = RvaToOffset(rva);
            if (o < 0) return "";
            var sb = new StringBuilder();
            for (int i = 0; i < max && o + i < _data.Length; i++)
            {
                byte b = _data[o + i];
                if (b == 0) break;
                sb.Append((char)b);
            }
            return sb.ToString();
        }

        /// <summary>Parse the export directory (named and ordinal exports, forwarders).</summary>
        public List<PeExport> ReadExports()
        {
            var result = new List<PeExport>();
            var (expRva, expSize) = _dirs[(int)DataDirectory.Export];
            if (expRva == 0 || expSize == 0) return result;

            int dir = RvaToOffset(expRva);
            if (dir < 0) return result;

            uint ordinalBase = U32(dir + 16);
            uint numFunctions = U32(dir + 20);
            uint numNames = U32(dir + 24);
            uint addrFuncs = U32(dir + 28);
            uint addrNames = U32(dir + 32);
            uint addrOrdinals = U32(dir + 36);

            int funcsOff = RvaToOffset(addrFuncs);
            int namesOff = addrNames != 0 ? RvaToOffset(addrNames) : -1;
            int ordsOff = addrOrdinals != 0 ? RvaToOffset(addrOrdinals) : -1;
            if (funcsOff < 0) return result;

            // Map ordinal-index -> name (only some functions are named).
            var nameByIndex = new Dictionary<int, string>();
            if (namesOff >= 0 && ordsOff >= 0)
            {
                for (int i = 0; i < numNames; i++)
                {
                    uint nameRva = U32(namesOff + i * 4);
                    ushort ord = U16(ordsOff + i * 2);
                    nameByIndex[ord] = ReadCString(nameRva);
                }
            }

            uint expEnd = expRva + expSize;
            for (int i = 0; i < numFunctions; i++)
            {
                uint funcRva = U32(funcsOff + i * 4);
                if (funcRva == 0) continue;

                var ex = new PeExport
                {
                    Ordinal = (ushort)(ordinalBase + i),
                    Rva = funcRva,
                };
                if (nameByIndex.TryGetValue(i, out var nm)) ex.Name = nm;

                // A forwarder's "RVA" points inside the export directory to a
                // "Dll.Func" string instead of code.
                if (funcRva >= expRva && funcRva < expEnd)
                    ex.ForwarderTo = ReadCString(funcRva);

                result.Add(ex);
            }
            return result;
        }

        /// <summary>Parse the import descriptors and their thunks (by name and ordinal).</summary>
        public List<PeImport> ReadImports()
        {
            var result = new List<PeImport>();
            var (impRva, impSize) = _dirs[(int)DataDirectory.Import];
            if (impRva == 0) return result;

            int descOff = RvaToOffset(impRva);
            if (descOff < 0) return result;

            int ptr = Is64Bit ? 8 : 4;
            ulong ordinalFlag = Is64Bit ? 0x8000000000000000UL : 0x80000000UL;

            for (int d = 0; ; d++)
            {
                int o = descOff + d * 20;
                if (o + 20 > _data.Length) break;

                uint origThunk = U32(o);
                uint nameRva = U32(o + 12);
                uint firstThunk = U32(o + 16);
                if (origThunk == 0 && firstThunk == 0 && nameRva == 0) break; // terminator

                string dll = ReadCString(nameRva);
                uint lookupRva = origThunk != 0 ? origThunk : firstThunk;
                int lookupOff = RvaToOffset(lookupRva);
                int iatOff = RvaToOffset(firstThunk);
                if (lookupOff < 0) continue;

                for (int t = 0; ; t++)
                {
                    ulong thunk = Is64Bit ? U64(lookupOff + t * ptr) : U32(lookupOff + t * ptr);
                    if (thunk == 0) break;

                    var imp = new PeImport
                    {
                        ModuleName = dll,
                        IatRva = (uint)(firstThunk + t * ptr),
                    };
                    if ((thunk & ordinalFlag) != 0)
                    {
                        imp.Ordinal = (ushort)(thunk & 0xFFFF);
                    }
                    else
                    {
                        uint byNameRva = (uint)(thunk & 0x7FFFFFFF);
                        int byNameOff = RvaToOffset(byNameRva);
                        if (byNameOff >= 0)
                            imp.Name = ReadCString((uint)byNameRva + 2); // skip 2-byte Hint
                    }
                    result.Add(imp);
                }
            }
            return result;
        }
    }
}
