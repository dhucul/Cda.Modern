using System;
using System.Collections.Generic;
using Cda.Core.Model;
using Cda.Core.Pe;
using Cda.Core.Process;

namespace Cda.Core.Engine
{
    /// <summary>
    /// Discovers the operating system's <b>dialog-box-creating</b> functions in a
    /// target — the <c>user32</c> message-box / resource-template family
    /// (<c>MessageBox*</c>, <c>DialogBoxParam*</c>, <c>CreateDialogParam*</c>), the
    /// <c>comctl32</c> task dialog and property sheet, the <c>comdlg32</c> common
    /// dialogs (File Open/Save, Color, Font, Print, Page Setup, Find/Replace), and the
    /// <c>credui</c> credential prompts — resolved to their live entry-point addresses,
    /// so a <see cref="CaptureSession"/> can inline-hook them and attribute each dialog
    /// to the app function that raised it.
    ///
    /// This is deliberately the mirror-image filter of <see cref="ExportScanner"/>:
    /// where that scans the app's OWN modules and skips the OS, this scans exactly the
    /// handful of OS modules the dialog surface lives in and keeps only the dialog
    /// exports. Resolving by <b>export address</b> (not by the app's import table) means
    /// a dialog is caught however the program reached it — a static import, a
    /// <c>GetProcAddress</c>, a delay-load, or a call routed through a third-party DLL.
    /// Most of the resolved entries are the same kind the inline Windows-API path already
    /// splices (<see cref="ApiImportScanner"/> → <see cref="CaptureSession.Start"/>),
    /// so hooking them carries no new risk.
    ///
    /// Two entries are <b>not</b> plain openers and are special-cased by the caller
    /// (MainWindow), because the modern GUI surface reaches past flat exports:
    ///   * <c>combase!CoCreateInstance</c> is the choke point for the modern
    ///     <c>IFileDialog</c> COM picker (Open/Save). The host matches the requested
    ///     CLSID, then reads the created object's vtable to inline-hook
    ///     <c>IFileDialog::Show</c> — so the picker is caught however it was wrapped
    ///     (native, MFC, WPF/.NET).
    ///   * <c>user32!CreateWindowEx</c> is the only lever for a <b>hand-rolled modal
    ///     window</b> (a custom-class window with its own message loop — no dialog API
    ///     at all). The host filters it down to dialog-like windows.
    /// Both are hotter than the openers; the caller protects them from the runaway
    /// auto-unhook (except CreateWindowEx, which it may drop if it floods) and does not
    /// emit a row per raw call.
    ///
    /// Several of these hosts (<c>comdlg32</c>, <c>credui</c>) load <b>lazily</b> — on
    /// first use, not at startup — so the launch loop re-scans on their LOAD_DLL event
    /// (see <see cref="IsDialogHostModule"/>). If no dialog host is mapped (a console
    /// app that never loads the GUI surface), <see cref="Result.Functions"/> is empty
    /// and the caller reports that plainly.
    /// </summary>
    public static class DialogApiScanner
    {
        // Same read cap as the sibling scanners; the dialog-host DLLs are well under it.
        private const long MaxModuleImageBytes = 96L * 1024 * 1024;

        // The OS modules the dialog surface lives in. ole32/combase are here only for
        // the CoCreateInstance choke point (see below); ole32's CoCreateInstance is a
        // forwarder to combase, so combase is where the real entry is hooked.
        private static readonly HashSet<string> DialogModules = new(StringComparer.OrdinalIgnoreCase)
        {
            "user32.dll", "comctl32.dll", "comdlg32.dll", "credui.dll",
            "ole32.dll", "combase.dll",
        };

        // Dialog-creating exports, by BASE name (A/W folded away — the export table
        // carries the suffixed forms, e.g. MessageBoxW). EndDialog is the closer, not an
        // opener, so it is intentionally absent, as are the cmd-line credential prompts.
        private static readonly HashSet<string> DialogApis = new(StringComparer.OrdinalIgnoreCase)
        {
            // user32 — message boxes and resource-template dialogs. The *Param* forms
            // are the real exports; DialogBox/CreateDialog are SDK macros over them.
            "MessageBox", "MessageBoxEx", "MessageBoxIndirect", "MessageBoxTimeout",
            "DialogBoxParam", "DialogBoxIndirectParam",
            "CreateDialogParam", "CreateDialogIndirectParam",
            // comctl32 — task dialogs and the tabbed property sheet.
            "TaskDialog", "TaskDialogIndirect", "PropertySheet",
            // comdlg32 — the common dialogs. Each takes a single struct pointer, so the
            // dialog is named but its caption is left blank unless the host can decode it.
            "GetOpenFileName", "GetSaveFileName", "ChooseColor", "ChooseFont",
            "PrintDlg", "PrintDlgEx", "PageSetupDlg", "FindText", "ReplaceText",
            // credui — the interactive credential prompts (not the CmdLine forms).
            "CredUIPromptForCredentials", "CredUIPromptForWindowsCredentials",
            // Special-cased by the caller — these are NOT plain openers and are hotter
            // than the rest, so MainWindow treats them specially rather than reporting a
            // row per call. CoCreateInstance is the choke point for the modern IFileDialog
            // COM picker (the host matches the CLSID, then reads the created object's
            // vtable to hook IFileDialog::Show). CreateWindowEx is the only lever for a
            // hand-rolled modal window (the host filters it down to dialog-like windows,
            // and it is the one dialog-mode hook the runaway guard may drop if it floods).
            // See MainWindow.HandleComCreate / IsDialogLikeWindow.
            "CoCreateInstance", "CreateWindowEx",
        };

        public sealed class Result
        {
            /// <summary>One <see cref="TracedFunction"/> per distinct resolved dialog entry.</summary>
            public List<TracedFunction> Functions = new();

            /// <summary>The OS modules those entries live in (for the views/graph).</summary>
            public List<ModuleInfo> Modules = new();

            /// <summary>Dialog-surface modules that were present and scanned.</summary>
            public List<ModuleInfo> ScannedModules = new();

            /// <summary>Dialog exports dropped because they forward to another DLL.</summary>
            public int SkippedForwarders;
        }

        /// <summary>
        /// Is <paramref name="fileName"/> (a bare module file name, e.g.
        /// <c>"comdlg32.dll"</c>) one of the OS modules the dialog surface lives in? The
        /// launch loop uses this to recognize a dialog host as it maps — several
        /// (comdlg32, credui) load lazily on first use rather than at startup, so they
        /// must be armed on their LOAD_DLL event, not just at the loader breakpoint.
        /// </summary>
        public static bool IsDialogHostModule(string? fileName) =>
            !string.IsNullOrEmpty(fileName) && DialogModules.Contains(fileName!);

        /// <summary>
        /// Walk the export tables of the target's dialog-surface modules and return
        /// their dialog-creating functions, resolved in <paramref name="process"/>.
        /// Read-only against the target.
        /// </summary>
        public static Result Discover(TargetProcess process, ModuleMap map)
        {
            var result = new Result();

            var seen = new HashSet<ulong>();
            var nodeModules = new Dictionary<ulong, ModuleInfo>();

            foreach (var module in map.Modules)
            {
                if (!IsDialogModule(module)) continue;
                if (module.Size == 0) continue;
                if (module.Size > (ulong)MaxModuleImageBytes) continue;

                byte[]? image = ReadImage(process, module);
                if (image == null) continue;

                PeImage pe;
                try { pe = PeImage.FromMappedImage(image, module.BaseAddress); }
                catch { continue; } // not a readable PE image right now — skip

                List<PeExport> exports;
                try { exports = pe.ReadExports(); }
                catch { continue; }

                bool scannedAny = false;
                foreach (var exp in exports)
                {
                    if (exp.Name == null) continue;         // dialog exports are all named
                    if (!IsDialogExport(exp.Name)) continue;
                    if (exp.IsForwarder) { result.SkippedForwarders++; continue; }
                    if (exp.Rva == 0) continue;             // hole in the export-address table

                    ulong target = module.BaseAddress + exp.Rva;
                    if (!seen.Add(target)) continue;

                    string declared = TrimDllExtension(module.Name);
                    string label = declared.Length > 0 ? declared + "!" + exp.Name : exp.Name;

                    result.Functions.Add(new TracedFunction(target, module.BaseAddress, label));
                    nodeModules[module.BaseAddress] = module;
                    scannedAny = true;
                }

                if (scannedAny) result.ScannedModules.Add(module);
            }

            foreach (var m in nodeModules.Values) result.Modules.Add(m);

            // Tidy, stable ordering: group by module, then function name.
            result.Functions.Sort((a, b) =>
                string.Compare(a.DisplayName, b.DisplayName, StringComparison.OrdinalIgnoreCase));

            return result;
        }

        // Is this one of the OS dialog-host DLLs, matched by file name (not path, so a
        // relocated system32 still matches; a same-named app DLL is vanishingly rare
        // and would only add a few harmless extra hook candidates).
        private static bool IsDialogModule(ModuleInfo m)
        {
            string name = m.Name;
            if (string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(m.Path))
                name = System.IO.Path.GetFileName(m.Path!);
            return !string.IsNullOrEmpty(name) && DialogModules.Contains(name);
        }

        // Match an export name against the dialog set: exact (TaskDialog*, which have
        // no A/W suffix), else fold a trailing A/W and retry (MessageBoxW -> MessageBox).
        private static bool IsDialogExport(string name)
        {
            if (DialogApis.Contains(name)) return true;
            if (name.Length > 1)
            {
                char last = name[name.Length - 1];
                if (last == 'A' || last == 'W') // real export suffixes are uppercase
                    return DialogApis.Contains(name.Substring(0, name.Length - 1));
            }
            return false;
        }

        // Read a module's mapped image into a managed buffer, chunked so an unreadable
        // page leaves a zero gap instead of failing the whole read. Mirrors
        // ExportScanner.ReadImage / ApiImportScanner.ReadImage.
        private static byte[]? ReadImage(TargetProcess process, ModuleInfo module)
        {
            int size = (int)Math.Min(module.Size, (ulong)int.MaxValue);
            if (size <= 0) return null;

            byte[] image;
            try { image = new byte[size]; }
            catch (OutOfMemoryException) { return null; }

            const int chunk = 0x10000;
            bool any = false;
            for (int off = 0; off < size; off += chunk)
            {
                int len = Math.Min(chunk, size - off);
                int read = process.ReadMemory(module.BaseAddress + (ulong)off, image.AsSpan(off, len));
                if (read > 0) any = true;
            }
            return any ? image : null;
        }

        private static string TrimDllExtension(string name)
        {
            if (string.IsNullOrEmpty(name)) return "";
            if (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                return name.Substring(0, name.Length - 4);
            return name;
        }
    }
}
