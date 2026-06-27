using System;
using System.Collections.Generic;

namespace DataVanger.Engine.ProtectedFiles;

/// <summary>
/// Conservative extension-transition analyzer for the Protected Files
/// Activity Monitor (Phase 2 / Step 07).
///
/// It looks at rename transitions (old extension → new extension) and
/// flags ransomware-like patterns: a common personal-document extension
/// being replaced by a known ransom-style extension or by an
/// unknown/random-looking extension.
///
/// Anti-FP guarantee:
///   A suspicious transition is descriptive EVIDENCE only. Ordinary
///   refactors, archive extraction, and build output produce no
///   suspicious transitions. Nothing here confirms malware.
/// </summary>
public static class ExtensionTransitionAnalyzer
{
    // Common personal document/media extensions worth protecting.
    private static readonly HashSet<string> CommonDocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf",
        ".csv", ".odt", ".ods", ".odp", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
        ".tif", ".tiff", ".raw", ".psd", ".mp3", ".mp4", ".avi", ".mov", ".mkv",
        ".zip", ".rar", ".7z", ".sql", ".mdb", ".accdb", ".pst", ".dwg",
    };

    // Known ransom-style replacement extensions (suffixes, label-only).
    private static readonly HashSet<string> KnownSuspiciousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".locked", ".encrypted", ".enc", ".crypt", ".crypted", ".crypto", ".cry",
        ".vault", ".cerber", ".locky", ".zepto", ".odin", ".aesir", ".wcry",
        ".wncry", ".wannacry", ".kraken", ".darkness", ".rumba", ".pays",
        ".ransom", ".lock", ".coded", ".krab", ".gdcb",
    };

    private static readonly HashSet<string> BenignTransientExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".tmp", ".temp", ".bak", ".old", ".swp", ".part", ".crdownload", ".partial",
    };

    /// <summary>Extracts the lowercase extension (with dot) from a path; empty when none.</summary>
    public static string GetExtension(string? path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        try
        {
            var ext = System.IO.Path.GetExtension(path);
            return string.IsNullOrEmpty(ext) ? string.Empty : ext.ToLowerInvariant();
        }
        catch (System.Exception)
        {
            return string.Empty;
        }
    }

    public static bool IsCommonDocumentExtension(string? extension)
        => !string.IsNullOrEmpty(extension) && CommonDocumentExtensions.Contains(extension!);

    public static bool IsKnownSuspiciousExtension(string? extension)
        => !string.IsNullOrEmpty(extension) && KnownSuspiciousExtensions.Contains(extension!);

    /// <summary>
    /// A new extension is "random-looking" when it is non-empty, not a
    /// common/benign extension, and either unusually long or composed of
    /// an unlikely character mix. Conservative by design.
    /// </summary>
    public static bool IsRandomLookingExtension(string? extension)
    {
        if (string.IsNullOrEmpty(extension)) return false;
        if (CommonDocumentExtensions.Contains(extension!)) return false;
        if (BenignTransientExtensions.Contains(extension!)) return false;

        var body = extension!.TrimStart('.');
        if (body.Length == 0) return false;

        // Long opaque extensions (e.g. ".a1b2c3d4e5") are ransom-like.
        if (body.Length >= 8) return true;

        // Mixed digits+letters in a short extension is mildly unusual but
        // common (e.g. ".mp3"), so we only treat length as the signal here
        // to stay conservative.
        return false;
    }

    public readonly struct Transition
    {
        public Transition(string fromExtension, string toExtension)
        {
            FromExtension = fromExtension;
            ToExtension = toExtension;
        }

        public string FromExtension { get; }
        public string ToExtension { get; }

        public bool HasChange =>
            !string.IsNullOrEmpty(ToExtension) &&
            !string.Equals(FromExtension, ToExtension, StringComparison.OrdinalIgnoreCase);

        public string Key => $"{(string.IsNullOrEmpty(FromExtension) ? "<none>" : FromExtension)}->{(string.IsNullOrEmpty(ToExtension) ? "<none>" : ToExtension)}";
    }

    /// <summary>Builds the from→to transition for a rename, using previous and current paths.</summary>
    public static Transition GetTransition(string? previousPath, string? currentPath)
        => new(GetExtension(previousPath), GetExtension(currentPath));

    /// <summary>
    /// True when a transition is suspicious: a known document type being
    /// replaced by a known ransom-style or random-looking extension, or
    /// any change to a known ransom-style extension. Benign transient
    /// transitions (.tmp/.bak/...) are never suspicious.
    /// </summary>
    public static bool IsSuspiciousTransition(in Transition transition)
    {
        if (!transition.HasChange) return false;

        var to = transition.ToExtension;
        if (BenignTransientExtensions.Contains(to)) return false;

        if (IsKnownSuspiciousExtension(to)) return true;

        // Document → unknown/random-looking extension.
        if (IsCommonDocumentExtension(transition.FromExtension) &&
            (IsRandomLookingExtension(to) || (!CommonDocumentExtensions.Contains(to) && to.Length >= 6)))
        {
            return true;
        }

        return false;
    }

    /// <summary>Convenience overload working directly on paths.</summary>
    public static bool IsSuspiciousTransition(string? previousPath, string? currentPath)
        => IsSuspiciousTransition(GetTransition(previousPath, currentPath));
}
