using System;
using System.IO;
using Cda.Core.Pe;

namespace Cda.Core.Process
{
    /// <summary>
    /// Produces a launchable copy of a PE image with its ASLR opt-in bits
    /// (DYNAMIC_BASE / HIGH_ENTROPY_VA) stripped, so the OS loader maps it at its
    /// preferred ImageBase every run. This is the reliable per-image way to get a
    /// fixed, reproducible base for a capture: the per-process bottom-up mitigation
    /// policy alone does not move a /DYNAMICBASE main image on current Windows, so a
    /// "Disable ASLR" launch strips the image too.
    ///
    /// The copy is written NEXT TO the original (same directory) so the target's
    /// implicitly-linked sibling DLLs still resolve from the application directory.
    /// Copies are uniquely named so relaunching while a previous (detached) capture
    /// is still running won't collide on a locked file; stale, unlocked copies are
    /// swept on the next call. For the preferred base to actually be honored,
    /// system-wide mandatory ASLR (force-relocate) must be off.
    /// </summary>
    public static class FixedBaseImage
    {
        // <name>.cdafb.<token><ext> — e.g. app.cdafb.1a2b3c.exe
        private const string Mid = ".cdafb.";

        /// <summary>
        /// Write a fixed-base (ASLR-stripped) copy of <paramref name="originalPath"/>
        /// next to it and return the copy's path. If the image already has ASLR off,
        /// or can't be parsed as a PE, returns <paramref name="originalPath"/>
        /// unchanged. Throws only if reading the original or writing the copy fails.
        /// </summary>
        public static string Create(string originalPath)
        {
            byte[] bytes = File.ReadAllBytes(originalPath);
            if (!PeImage.TryStripAslr(bytes)) return originalPath; // already non-ASLR / not a PE

            CleanupNear(originalPath); // sweep stale, unlocked copies before writing a fresh one

            string dir = Path.GetDirectoryName(originalPath) ?? ".";
            string name = Path.GetFileNameWithoutExtension(originalPath);
            string ext = Path.GetExtension(originalPath);
            string token = Environment.TickCount64.ToString("x");
            string copy = Path.Combine(dir, name + Mid + token + ext);
            File.WriteAllBytes(copy, bytes);
            return copy;
        }

        /// <summary>True if <paramref name="path"/> names one of our fixed-base copies.</summary>
        public static bool IsCopy(string path) =>
            Path.GetFileName(path).Contains(Mid, StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Best-effort removal of fixed-base copies previously written next to
        /// <paramref name="originalPath"/>. A copy still locked by a running capture
        /// is left in place (it'll be swept on a later call).
        /// </summary>
        public static void CleanupNear(string originalPath)
        {
            try
            {
                string dir = Path.GetDirectoryName(originalPath) ?? ".";
                string name = Path.GetFileNameWithoutExtension(originalPath);
                string ext = Path.GetExtension(originalPath);
                foreach (var f in Directory.GetFiles(dir, name + Mid + "*" + ext))
                {
                    try { File.Delete(f); } catch { /* locked by a live capture — leave it */ }
                }
            }
            catch { /* directory not enumerable — ignore */ }
        }
    }
}
