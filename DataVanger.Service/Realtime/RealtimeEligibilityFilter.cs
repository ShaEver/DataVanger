using System;
using System.Collections.Generic;
using System.IO;
using DataVanger.Shared.Realtime;

namespace DataVanger.Service.Realtime;

/// <summary>
/// Decides whether a normalized <see cref="RealtimeFileEvent"/> should
/// be promoted to a scan request. The filter is conservative: when in
/// doubt, skip — manual / deep scans always remain free to inspect.
///
/// Anti-FP guarantee: skipping a file is NEVER a malware verdict; it is
/// telemetry that the orchestrator surfaces as a status warning at
/// most, and never as a finding.
/// </summary>
public sealed class RealtimeEligibilityFilter
{
    private static readonly string[] DefaultIncludeExtensions = new[]
    {
        ".exe", ".dll", ".scr", ".com", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".jse", ".wsf",
        ".msi", ".jar",
        ".zip", ".7z", ".rar",
        ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
        ".pdf",
        ".json", // browser-extension manifests etc.
    };

    private static readonly string[] DevelopmentModeExcludeFragments = new[]
    {
        $"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}",
        $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
        $"{Path.DirectorySeparatorChar}.git{Path.DirectorySeparatorChar}",
        $"{Path.DirectorySeparatorChar}.vs{Path.DirectorySeparatorChar}",
        $"{Path.DirectorySeparatorChar}TestResults{Path.DirectorySeparatorChar}",
        $"{Path.DirectorySeparatorChar}coverage{Path.DirectorySeparatorChar}",
    };

    private static readonly string[] DevelopmentModeExcludeSuffixes = new[]
    {
        ".user", ".suo", ".tmp",
    };

    private readonly RealtimeProtectionOptions _options;

    public RealtimeEligibilityFilter(RealtimeProtectionOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public bool TryAccept(RealtimeFileEvent ev, RealtimeWatchProfile profile, out string? skipReason)
    {
        skipReason = null;
        if (ev is null) { skipReason = "null event"; return false; }
        if (profile is null) { skipReason = "null profile"; return false; }
        if (string.IsNullOrWhiteSpace(ev.Path)) { skipReason = "empty path"; return false; }

        // Deleted paths never scan.
        if (ev.Kind == RealtimeFileEventKind.Deleted) { skipReason = "deleted"; return false; }

        // Lifecycle events flow through other channels.
        if (ev.Kind == RealtimeFileEventKind.WatcherStarted
            || ev.Kind == RealtimeFileEventKind.WatcherStopped
            || ev.Kind == RealtimeFileEventKind.WatcherError)
        {
            skipReason = "lifecycle event";
            return false;
        }

        var path = ev.Path;

        if (MatchesAnyFragment(path, DevelopmentModeExcludeFragments)
            && (_options.DevelopmentMode || profile.DevelopmentSafe))
        {
            skipReason = "development-mode excluded path";
            return false;
        }

        if (profile.ExcludePathFragments.Count > 0
            && MatchesAnyFragment(path, profile.ExcludePathFragments))
        {
            skipReason = "profile-excluded path fragment";
            return false;
        }

        var ext = Path.GetExtension(path);
        var lowerExt = string.IsNullOrEmpty(ext) ? string.Empty : ext.ToLowerInvariant();

        if ((_options.DevelopmentMode || profile.DevelopmentSafe)
            && EndsWithAny(path, DevelopmentModeExcludeSuffixes))
        {
            skipReason = "development-mode excluded suffix";
            return false;
        }

        if (profile.ExcludeExtensions.Count > 0)
        {
            foreach (var x in profile.ExcludeExtensions)
            {
                if (string.Equals(x, lowerExt, StringComparison.OrdinalIgnoreCase))
                {
                    skipReason = "profile-excluded extension";
                    return false;
                }
            }
        }

        IReadOnlyList<string> includeSet = profile.IncludeExtensions.Count > 0
            ? profile.IncludeExtensions
            : DefaultIncludeExtensions;

        if (!string.IsNullOrEmpty(lowerExt))
        {
            foreach (var x in includeSet)
            {
                if (string.Equals(x, lowerExt, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            skipReason = "extension not in include list";
            return false;
        }

        // No extension: accept only if the profile explicitly opts in
        // by listing the empty string. Otherwise skip — bare files in
        // arbitrary directories are too noisy for a default real-time
        // policy and remain visible to manual scans.
        foreach (var x in includeSet)
        {
            if (string.IsNullOrEmpty(x))
            {
                return true;
            }
        }
        skipReason = "extension-less file (skipped in real-time)";
        return false;
    }

    private static bool MatchesAnyFragment(string path, IReadOnlyList<string> fragments)
    {
        for (int i = 0; i < fragments.Count; i++)
        {
            if (path.IndexOf(fragments[i], StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
        }
        return false;
    }

    private static bool EndsWithAny(string path, IReadOnlyList<string> suffixes)
    {
        for (int i = 0; i < suffixes.Count; i++)
        {
            if (path.EndsWith(suffixes[i], StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
