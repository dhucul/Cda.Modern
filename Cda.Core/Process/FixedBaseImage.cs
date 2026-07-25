using System;
using System.Collections.Concurrent;
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
    /// is still running won't collide on a locked file. Cleanup is restricted to
    /// paths this process created and recorded as owned. For the preferred base to
    /// actually be honored, system-wide mandatory ASLR (force-relocate) must be off.
    /// </summary>
    public static class FixedBaseImage
    {
        // <name>.cdafb.<token><ext> — e.g. app.cdafb.1a2b3c.exe
        private const string Mid = ".cdafb.";
        private static readonly ConcurrentDictionary<string, string> OwnedCopies =
            new(StringComparer.OrdinalIgnoreCase);
        private static readonly object Gate = new();

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

            lock (Gate)
            {
                CleanupOwnedCopies(originalPath);

                string dir = Path.GetDirectoryName(originalPath) ?? ".";
                string name = Path.GetFileNameWithoutExtension(originalPath);
                string ext = Path.GetExtension(originalPath);
                string token = Guid.NewGuid().ToString("N");
                string copy = Path.Combine(dir, name + Mid + token + ext);
                File.WriteAllBytes(copy, bytes);
                OwnedCopies[Path.GetFullPath(copy)] = Path.GetFullPath(originalPath);
                return copy;
            }
        }

        /// <summary>True if <paramref name="path"/> names one of our fixed-base copies.</summary>
        public static bool IsCopy(string path) =>
            Path.GetFileName(path).Contains(Mid, StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Best-effort removal of fixed-base copies this process previously wrote
        /// for <paramref name="originalPath"/>. A copy still locked by a running
        /// capture remains owned and can be retried later in this process.
        /// </summary>
        public static void CleanupNear(string originalPath)
        {
            lock (Gate)
            {
                CleanupOwnedCopies(originalPath);
            }
        }

        private static void CleanupOwnedCopies(string originalPath)
        {
            string fullOriginal;
            try { fullOriginal = Path.GetFullPath(originalPath); }
            catch { return; }

            foreach (var entry in OwnedCopies)
            {
                if (!PathClassifier.SameFile(entry.Value, fullOriginal)) continue;
                try
                {
                    if (File.Exists(entry.Key)) File.Delete(entry.Key);
                    OwnedCopies.TryRemove(entry.Key, out _);
                }
                catch { /* locked by a live capture — retain ownership and retry later */ }
            }
        }
    }
}
