using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace DataVanger.Engine.Remediation.Policy;

/// <summary>
/// Conservative detector for protected system files/paths. Used to feed
/// <see cref="RemediationPolicyRequest.IsSystemFile"/> so the policy can refuse
/// remediating an OS-critical file on anything weaker than ConfirmedMalware. When
/// in doubt it errs toward "system" (conservative), and it never mutates anything.
/// </summary>
public sealed class SystemFileGuard
{
    private readonly IReadOnlyList<string> _protectedRoots;

    public SystemFileGuard(IEnumerable<string>? additionalProtectedRoots = null)
    {
        var roots = new List<string>();
        foreach (var folder in new[]
                 {
                     Environment.SpecialFolder.Windows,
                     Environment.SpecialFolder.System,
                     Environment.SpecialFolder.SystemX86,
                     Environment.SpecialFolder.ProgramFiles,
                     Environment.SpecialFolder.ProgramFilesX86,
                 })
        {
            var p = SafeGetFolder(folder);
            if (!string.IsNullOrEmpty(p)) roots.Add(p);
        }

        // Curated Unix system roots so the guard is meaningful and testable on every platform.
        roots.AddRange(new[] { "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/boot", "/proc", "/sys", "/dev" });

        if (additionalProtectedRoots is not null)
            roots.AddRange(additionalProtectedRoots.Where(r => !string.IsNullOrWhiteSpace(r)));

        _protectedRoots = roots.Select(NormalizeRoot).Where(r => r.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>True when the path is under a protected system root, or cannot be
    /// normalized (fail conservative).</summary>
    public bool IsSystemFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return true; // unknown → conservative
        string normalized;
        try { normalized = Path.GetFullPath(path); }
        catch { return true; } // unparseable → conservative

        var compare = NormalizeRoot(normalized);
        foreach (var root in _protectedRoots)
        {
            if (compare.Equals(root, StringComparison.OrdinalIgnoreCase)
                || compare.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || compare.StartsWith(root + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static string SafeGetFolder(Environment.SpecialFolder folder)
    {
        try { return Environment.GetFolderPath(folder); }
        catch { return string.Empty; }
    }

    private static string NormalizeRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return string.Empty;
        try { return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar); }
        catch { return path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar); }
    }
}
