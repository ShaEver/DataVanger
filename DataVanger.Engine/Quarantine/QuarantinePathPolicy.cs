using System;
using System.IO;
using System.Linq;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Engine.Quarantine;

/// <summary>
/// Restore path-safety validation (Secure Quarantine V2).
///
/// Restore is the only operation that writes outside the controlled quarantine
/// store, so every destination is normalized and validated before any bytes are
/// written. The policy refuses:
///   - empty/relative/non-rooted paths;
///   - paths containing traversal segments ("..");
///   - paths whose normalized form escapes into a forbidden root (the
///     quarantine store itself, or any configured program/runtime directory);
///   - paths that resolve to a directory.
///
/// It is deliberately conservative: when in doubt, refuse.
/// </summary>
public static class QuarantinePathPolicy
{
    public readonly struct ValidationOutcome
    {
        public ValidationOutcome(bool isValid, string normalizedPath, string reason)
        {
            IsValid = isValid;
            NormalizedPath = normalizedPath;
            Reason = reason;
        }

        public bool IsValid { get; }
        public string NormalizedPath { get; }
        public string Reason { get; }

        public static ValidationOutcome Valid(string normalized) => new(true, normalized, string.Empty);
        public static ValidationOutcome Invalid(string reason) => new(false, string.Empty, reason);
    }

    public static ValidationOutcome ValidateRestoreDestination(
        string? candidatePath,
        string quarantineStoreRoot,
        QuarantineOptions options)
    {
        if (string.IsNullOrWhiteSpace(candidatePath))
            return ValidationOutcome.Invalid("Destination path is empty.");

        // Reject traversal before normalization collapses it away.
        var rawSegments = candidatePath.Split('/', '\\');
        if (rawSegments.Any(s => s == ".."))
            return ValidationOutcome.Invalid("Destination path contains traversal segments ('..').");

        if (candidatePath.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
            return ValidationOutcome.Invalid("Destination path contains invalid characters.");

        // Alternate-data-stream suffix abuse (path:stream) is refused.
        var fileNamePart = candidatePath.Split('/', '\\').LastOrDefault() ?? string.Empty;
        if (fileNamePart.Contains(':'))
            return ValidationOutcome.Invalid("Destination file name contains an alternate-data-stream separator.");

        string normalized;
        try
        {
            normalized = Path.GetFullPath(candidatePath);
        }
        catch (Exception ex)
        {
            return ValidationOutcome.Invalid("Destination path could not be normalized: " + ex.GetType().Name);
        }

        if (!Path.IsPathRooted(normalized))
            return ValidationOutcome.Invalid("Destination path is not rooted.");

        if (Directory.Exists(normalized))
            return ValidationOutcome.Invalid("Destination path refers to an existing directory.");

        // Always forbid restoring into the quarantine store internals.
        if (IsUnderRoot(normalized, quarantineStoreRoot))
            return ValidationOutcome.Invalid("Destination is inside the quarantine store.");

        foreach (var forbidden in options.ForbiddenRestoreRoots)
        {
            if (!string.IsNullOrWhiteSpace(forbidden) && IsUnderRoot(normalized, forbidden))
                return ValidationOutcome.Invalid("Destination is inside a protected/runtime directory.");
        }

        return ValidationOutcome.Valid(normalized);
    }

    private static bool IsUnderRoot(string fullPath, string root)
    {
        if (string.IsNullOrWhiteSpace(root)) return false;
        string normalizedRoot;
        try { normalizedRoot = Path.GetFullPath(root); }
        catch (System.Exception) { return false; }

        normalizedRoot = normalizedRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

        if (string.Equals(fullPath, normalizedRoot, comparison)) return true;
        return fullPath.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, comparison);
    }
}
