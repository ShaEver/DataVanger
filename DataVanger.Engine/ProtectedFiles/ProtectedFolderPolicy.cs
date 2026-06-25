using System;
using System.Collections.Generic;
using DataVanger.Shared.ProtectedFiles;

namespace DataVanger.Engine.ProtectedFiles;

/// <summary>
/// Classification of a single path for the Protected Files Activity
/// Monitor (Phase 2 / Step 07).
/// </summary>
public enum PathClass
{
    /// <summary>Not in any configured protected/dev/excluded root.</summary>
    Other = 0,

    /// <summary>A protected user folder (Documents, Desktop, ...). Activity here is scored up.</summary>
    Protected,

    /// <summary>A development/build path (bin, obj, .git, ...). Activity here is heavily down-scored.</summary>
    DevelopmentSafe,

    /// <summary>An explicitly excluded path. Activity here is ignored for scoring.</summary>
    Excluded,
}

/// <summary>
/// Decides whether a path lives in a protected user folder, a
/// development-safe/build folder, or an excluded folder.
///
/// CRITICAL development safety:
///   Development and build folders are always heavily down-scored (or
///   excluded) so that <c>dotnet build</c>, test output, git operations,
///   and package extraction NEVER trip the monitor. The monitor only
///   scores; it never blocks any path.
/// </summary>
public sealed class ProtectedFolderPolicy
{
    // Built-in protected user folder fragments (matched case-insensitively).
    private static readonly string[] DefaultProtectedFragments =
    {
        "\\documents\\", "/documents/",
        "\\desktop\\", "/desktop/",
        "\\pictures\\", "/pictures/",
        "\\videos\\", "/videos/",
        "\\music\\", "/music/",
        "\\onedrive\\", "/onedrive/",
    };

    // Built-in development/build/test fragments that must stay safe.
    private static readonly string[] DefaultDevelopmentFragments =
    {
        "\\bin\\", "/bin/",
        "\\obj\\", "/obj/",
        "\\.git\\", "/.git/",
        "\\.vs\\", "/.vs/",
        "\\node_modules\\", "/node_modules/",
        "\\packages\\", "/packages/",
        "\\.nuget\\", "/.nuget/",
        "\\.cargo\\", "/.cargo/",
        "\\target\\", "/target/",
        "\\dist\\", "/dist/",
        "\\build\\", "/build/",
        "datavangertest", "datavanger_test", "\\temp\\", "/temp/", "\\tmp\\", "/tmp/",
    };

    private readonly List<string> _protected = new();
    private readonly List<string> _development = new();
    private readonly List<string> _excluded = new();
    private readonly bool _protectedMonitoringEnabled;

    public ProtectedFolderPolicy(ProtectedFilesActivityOptions options)
    {
        options ??= ProtectedFilesActivityOptions.DevelopmentSafe();
        _protectedMonitoringEnabled = options.EnableProtectedFolderMonitoring;

        if (options.ProtectedFolderRoots is { Count: > 0 })
            AddNormalized(_protected, options.ProtectedFolderRoots);
        else
            _protected.AddRange(DefaultProtectedFragments);

        if (options.DevelopmentSafeRoots is { Count: > 0 })
            AddNormalized(_development, options.DevelopmentSafeRoots);
        else
            _development.AddRange(DefaultDevelopmentFragments);

        // Built-in development fragments are ALWAYS honored on top of any
        // caller-supplied dev roots, so build/test output can never be
        // accidentally un-protected by overriding the list.
        foreach (var frag in DefaultDevelopmentFragments)
        {
            if (!_development.Contains(frag)) _development.Add(frag);
        }

        if (options.ExcludedRoots is { Count: > 0 })
            AddNormalized(_excluded, options.ExcludedRoots);
    }

    /// <summary>Classifies a path. Never throws. Excluded/Development win over Protected.</summary>
    public PathClass Classify(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return PathClass.Other;
        var normalized = Normalize(path!);

        if (ContainsAny(normalized, _excluded)) return PathClass.Excluded;

        // Development/build safety takes precedence over "protected" so a
        // protected folder that also contains a build dir stays safe.
        if (ContainsAny(normalized, _development)) return PathClass.DevelopmentSafe;

        if (_protectedMonitoringEnabled && ContainsAny(normalized, _protected)) return PathClass.Protected;

        return PathClass.Other;
    }

    public bool IsProtected(string? path) => Classify(path) == PathClass.Protected;
    public bool IsDevelopmentSafe(string? path) => Classify(path) == PathClass.DevelopmentSafe;
    public bool IsExcluded(string? path) => Classify(path) == PathClass.Excluded;

    /// <summary>Returns the directory portion of a path for folder-root grouping. Never throws.</summary>
    public static string? GetDirectory(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        try
        {
            var dir = System.IO.Path.GetDirectoryName(path);
            return string.IsNullOrEmpty(dir) ? null : dir;
        }
        catch
        {
            return null;
        }
    }

    private static void AddNormalized(List<string> target, IEnumerable<string> values)
    {
        foreach (var v in values)
        {
            if (string.IsNullOrWhiteSpace(v)) continue;
            target.Add(Normalize(v));
        }
    }

    private static bool ContainsAny(string normalizedPath, List<string> fragments)
    {
        foreach (var frag in fragments)
        {
            if (frag.Length == 0) continue;
            if (normalizedPath.Contains(frag, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    private static string Normalize(string value) => value.ToLowerInvariant();
}
