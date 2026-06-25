using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace DataVanger.Engine.Remediation.Files;

/// <summary>The decision of a safe-path evaluation. Conservative: when in doubt,
/// not safe.</summary>
public readonly record struct SafePathDecision(bool IsSafe, string NormalizedPath, string Reason)
{
    public static SafePathDecision Safe(string normalized) => new(true, normalized, string.Empty);
    public static SafePathDecision Unsafe(string reason) => new(false, string.Empty, reason);
}

/// <summary>
/// Decides whether a filesystem path is safe to remediate (delete/clean). This
/// is the system-file protection gate. It is pure (no I/O) and deliberately
/// conservative — it refuses on any doubt.
/// </summary>
public interface ISafePathPolicy
{
    SafePathDecision Evaluate(string? path);
    bool IsWithinTempRoot(string normalizedPath);
}

/// <summary>
/// Conservative default safe-path policy. Refuses:
///   - empty / relative / non-rooted paths;
///   - paths with traversal segments ("..");
///   - paths with invalid characters or an alternate-data-stream suffix;
///   - paths under a forbidden system root (Windows, System32, Program Files,
///     and a curated set of Unix system roots so the policy is meaningful and
///     testable on every platform);
///   - directories (a remediation target must be a file path form).
///
/// Reparse-point refusal is enforced at delete time via
/// <see cref="IFileSystemRemediationOperations.IsReparsePoint"/> (it needs the
/// real file), not here, because this policy is pure.
/// </summary>
public sealed class RemediationSafePathPolicy : ISafePathPolicy
{
    private readonly IReadOnlyList<string> _forbiddenRoots;
    private readonly string _tempRoot;

    public RemediationSafePathPolicy(IEnumerable<string>? additionalForbiddenRoots = null, string? tempRoot = null)
    {
        var roots = new List<string>();

        // Windows system roots (empty strings on non-Windows are skipped).
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

        // Curated Unix system roots so the denylist is testable on Linux too.
        roots.AddRange(new[] { "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/boot", "/proc", "/sys", "/dev" });

        if (additionalForbiddenRoots is not null)
            roots.AddRange(additionalForbiddenRoots.Where(r => !string.IsNullOrWhiteSpace(r)));

        _forbiddenRoots = roots
            .Select(NormalizeRoot)
            .Where(r => r.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        _tempRoot = NormalizeRoot(tempRoot ?? Path.GetTempPath());
    }

    public SafePathDecision Evaluate(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return SafePathDecision.Unsafe("Path is empty.");

        var rawSegments = path.Split('/', '\\');
        if (rawSegments.Any(s => s == ".."))
            return SafePathDecision.Unsafe("Path contains traversal segments ('..').");

        if (path.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
            return SafePathDecision.Unsafe("Path contains invalid characters.");

        var fileNamePart = rawSegments.LastOrDefault() ?? string.Empty;
        if (fileNamePart.Contains(':'))
            return SafePathDecision.Unsafe("File name contains an alternate-data-stream separator.");

        if (!Path.IsPathFullyQualified(path))
            return SafePathDecision.Unsafe("Path is not absolute.");

        string normalized;
        try
        {
            normalized = Path.GetFullPath(path);
        }
        catch (Exception ex)
        {
            return SafePathDecision.Unsafe("Path could not be normalized: " + ex.GetType().Name);
        }

        if (normalized.EndsWith(Path.DirectorySeparatorChar) || normalized.EndsWith(Path.AltDirectorySeparatorChar))
            return SafePathDecision.Unsafe("Path resolves to a directory.");

        var compare = NormalizeRoot(normalized);
        foreach (var root in _forbiddenRoots)
        {
            if (compare.Equals(root, StringComparison.OrdinalIgnoreCase)
                || compare.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || compare.StartsWith(root + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                return SafePathDecision.Unsafe($"Path is under a protected system root ('{root}').");
            }
        }

        return SafePathDecision.Safe(normalized);
    }

    public bool IsWithinTempRoot(string normalizedPath)
    {
        if (string.IsNullOrWhiteSpace(normalizedPath) || _tempRoot.Length == 0) return false;
        var compare = NormalizeRoot(normalizedPath);
        return compare.StartsWith(_tempRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            || compare.StartsWith(_tempRoot + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string SafeGetFolder(Environment.SpecialFolder folder)
    {
        try { return Environment.GetFolderPath(folder); }
        catch { return string.Empty; }
    }

    private static string NormalizeRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return string.Empty;
        try
        {
            var full = Path.GetFullPath(path);
            return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch
        {
            return path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
    }
}
