using System;
using System.IO;

namespace Cda.Core.Process
{
    public static class PathClassifier
    {
        public static bool IsUnderDirectory(string? path, string? root)
        {
            if (!TryNormalize(path, out string normalizedPath) ||
                !TryNormalize(root, out string normalizedRoot))
                return false;

            normalizedRoot = normalizedRoot.TrimEnd(
                Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (normalizedRoot.Length == 0) return false;

            return normalizedPath.StartsWith(
                normalizedRoot + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
        }

        public static bool SameFile(string? left, string? right)
        {
            return TryNormalize(left, out string normalizedLeft) &&
                   TryNormalize(right, out string normalizedRight) &&
                   string.Equals(normalizedLeft, normalizedRight,
                       StringComparison.OrdinalIgnoreCase);
        }

        public static bool TryNormalize(string? path, out string normalized)
        {
            normalized = "";
            if (string.IsNullOrWhiteSpace(path)) return false;

            string value = path.Trim();
            if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                value = @"\\" + value[8..];
            else if (value.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase))
                value = @"\\" + value[8..];
            else if (value.StartsWith(@"\\?\", StringComparison.Ordinal))
                value = value[4..];
            else if (value.StartsWith(@"\??\", StringComparison.Ordinal))
                value = value[4..];

            try
            {
                normalized = Path.GetFullPath(value)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                return normalized.Length != 0;
            }
            catch
            {
                return false;
            }
        }
    }
}
