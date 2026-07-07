using System;
using System.Collections.Generic;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Threading;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Disassembler;
using ICSharpCode.Decompiler.Metadata;

namespace Cda.Managed
{
    /// <summary>One method in a managed image (a browse entry in the function list).</summary>
    public sealed class ManagedMethod
    {
        public string Name = "";
        public string TypeName = "";
        public string FullName = "";  // Type.Method
        public int Token;             // metadata token (0x06xxxxxx)
        public uint BodyRva;          // IL body RVA (0 for abstract / pinvoke / no body)
        internal MethodDefinitionHandle Handle;
    }

    /// <summary>An embedded or linked manifest resource.</summary>
    public sealed class ManagedResourceInfo
    {
        public string Name = "";
        public bool Embedded;   // true: bytes live in this file (extractable)
        public int Size;        // uncompressed size for an embedded resource, else 0
    }

    /// <summary>
    /// Static view of a managed (.NET / CLI) assembly: enumerate its methods
    /// (name + metadata token + IL-body RVA), render a selected method's IL and
    /// decompiled C# (ILSpy's decompiler), and enumerate/extract embedded resources.
    ///
    /// This is the counterpart to the native <c>CallSiteScanner</c> discovery for a
    /// managed image, whose <c>.text</c> is IL + metadata and would decode as garbage
    /// through Iced. It touches no live process — it is purely a file view.
    /// </summary>
    public sealed class ManagedImage : IDisposable
    {
        private readonly PEFile _peFile;
        private readonly CSharpDecompiler _decompiler;
        private readonly List<ManagedMethod> _methods = new();
        private readonly List<ManagedResourceInfo> _resources = new();

        public string AssemblyName { get; }
        public IReadOnlyList<ManagedMethod> Methods => _methods;
        public IReadOnlyList<ManagedResourceInfo> Resources => _resources;

        private ManagedImage(PEFile peFile, CSharpDecompiler decompiler, string asmName)
        {
            _peFile = peFile;
            _decompiler = decompiler;
            AssemblyName = asmName;
        }

        /// <summary>Open a managed assembly from disk for static browsing.</summary>
        public static ManagedImage Load(string path)
        {
            // PrefetchEntireImage buffers the whole file in memory, so if anything after
            // this throws the PEFile must be disposed or that buffer leaks (the caller
            // swallows the throw and falls back to the native scan).
            var peFile = new PEFile(path, PEStreamOptions.PrefetchEntireImage);
            try
            {
                string tfm = "";
                try { tfm = peFile.DetectTargetFrameworkId() ?? ""; } catch { /* best effort */ }
                var resolver = new UniversalAssemblyResolver(path, throwOnError: false, tfm);
                var settings = new DecompilerSettings { ThrowOnAssemblyResolveErrors = false };
                var decompiler = new CSharpDecompiler(peFile, resolver, settings);

                var md = peFile.Metadata;
                string asmName;
                try { asmName = md.IsAssembly ? md.GetString(md.GetAssemblyDefinition().Name) : peFile.Name; }
                catch { asmName = peFile.Name; }

                var img = new ManagedImage(peFile, decompiler, asmName);
                img.EnumerateMethods(md);
                img.EnumerateResources(md);
                return img;
            }
            catch
            {
                peFile.Dispose();
                throw;
            }
        }

        private void EnumerateMethods(MetadataReader md)
        {
            foreach (var mh in md.MethodDefinitions)
            {
                MethodDefinition m;
                try { m = md.GetMethodDefinition(mh); } catch { continue; }

                string name;
                string typeName;
                try
                {
                    name = md.GetString(m.Name);
                    var td = md.GetTypeDefinition(m.GetDeclaringType());
                    string ns = md.GetString(td.Namespace);
                    string tn = md.GetString(td.Name);
                    typeName = ns.Length > 0 ? ns + "." + tn : tn;
                }
                catch { continue; }

                _methods.Add(new ManagedMethod
                {
                    Name = name,
                    TypeName = typeName,
                    FullName = typeName.Length > 0 ? typeName + "." + name : name,
                    Token = MetadataTokens.GetToken(mh),
                    BodyRva = (uint)m.RelativeVirtualAddress,
                    Handle = mh,
                });
            }

            _methods.Sort((a, b) =>
            {
                int c = string.CompareOrdinal(a.TypeName, b.TypeName);
                return c != 0 ? c : string.CompareOrdinal(a.Name, b.Name);
            });
        }

        private void EnumerateResources(MetadataReader md)
        {
            foreach (var rh in md.ManifestResources)
            {
                ManifestResource r;
                try { r = md.GetManifestResource(rh); } catch { continue; }
                bool embedded = r.Implementation.IsNil; // no external Implementation ⇒ bytes are in this file
                _resources.Add(new ManagedResourceInfo
                {
                    Name = md.GetString(r.Name),
                    Embedded = embedded,
                    Size = embedded ? TryResourceLength(r) : 0,
                });
            }
        }

        /// <summary>Decompiled C# for one method (best effort; never throws).</summary>
        public string DecompileCSharp(ManagedMethod m)
        {
            try { return _decompiler.DecompileAsString(new EntityHandle[] { m.Handle }); }
            catch (Exception ex) { return "// C# decompilation failed: " + ex.Message; }
        }

        /// <summary>IL disassembly for one method (best effort; never throws).</summary>
        public string DisassembleIL(ManagedMethod m)
        {
            try
            {
                var output = new PlainTextOutput();
                var dis = new ReflectionDisassembler(output, CancellationToken.None);
                dis.DisassembleMethod(_peFile, m.Handle);
                return output.ToString() ?? "";
            }
            catch (Exception ex) { return "// IL disassembly failed: " + ex.Message; }
        }

        /// <summary>Extract an embedded resource's raw bytes, or null if not embedded/found.</summary>
        public byte[]? ExtractResource(string name)
        {
            var md = _peFile.Metadata;
            foreach (var rh in md.ManifestResources)
            {
                ManifestResource r;
                try { r = md.GetManifestResource(rh); } catch { continue; }
                if (!r.Implementation.IsNil || md.GetString(r.Name) != name) continue;
                try
                {
                    var (block, ok) = ResourceBlock();
                    if (!ok) return null;
                    var lenReader = block.GetReader((int)r.Offset, 4);
                    int len = lenReader.ReadInt32();
                    if (len < 0) return null;
                    var dataReader = block.GetReader((int)r.Offset + 4, len);
                    return dataReader.ReadBytes(len);
                }
                catch { return null; }
            }
            return null;
        }

        private int TryResourceLength(ManifestResource r)
        {
            try
            {
                var (block, ok) = ResourceBlock();
                if (!ok) return 0;
                var reader = block.GetReader((int)r.Offset, 4);
                return reader.ReadInt32();
            }
            catch { return 0; }
        }

        private (PEMemoryBlock Block, bool Ok) ResourceBlock()
        {
            var corHeader = _peFile.Reader.PEHeaders.CorHeader;
            int rva = corHeader?.ResourcesDirectory.RelativeVirtualAddress ?? 0;
            if (rva == 0) return (default, false);
            return (_peFile.Reader.GetSectionData(rva), true);
        }

        public void Dispose() => _peFile.Dispose();
    }
}
