using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using DataVanger.Core;

namespace DataVanger.Engine;

/// <summary>
/// Builds the list of root paths a scan should walk based on the profile and
/// user settings. Lifted out of <c>ScanEngine</c> so unit tests can verify
/// the path-resolution rules without touching the filesystem walker.
/// </summary>
public static class TargetDiscovery
{
    public static IEnumerable<string> ResolveTargets(ScanProfile profile, AppSettings settings,
        DataVanger.Engine.DeepScanLayerConfig? deepConfig = null)
    {
        return profile switch
        {
            ScanProfile.Fast => ResolveFastTargets(settings),
            ScanProfile.Deep => ResolveDeepTargets(settings, deepConfig ?? DataVanger.Engine.DeepScanLayerConfig.Default),
            _ => ResolveDeepTargets(settings, deepConfig ?? DataVanger.Engine.DeepScanLayerConfig.Default)
        };
    }

    private static IEnumerable<string> ResolveFastTargets(AppSettings settings)
    {
        var up = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var app = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var pdata = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        var targets = new List<string>();
        void Add(string p) { if (!string.IsNullOrWhiteSpace(p)) targets.Add(p); }

        // Fast profile: minimal, user-centric targets only (no system areas, no full drives)
        Add(Path.Combine(up, "Downloads"));
        Add(Path.Combine(up, "Desktop"));
        Add(Path.GetTempPath());

        if (settings.ScanStartupLocations)
        {
            Add(Path.Combine(app, @"Microsoft\Windows\Start Menu\Programs\Startup"));
            Add(Path.Combine(pdata, @"Microsoft\Windows\Start Menu\Programs\Startup"));
        }

        if (settings.ScanAppData)
        {
            Add(app);
            Add(local);
        }

        foreach (var extra in settings.ExtraTargets.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            try { Add(Environment.ExpandEnvironmentVariables(extra)); }
            catch (Exception) { }
        }

        return RemoveContainedPaths(targets.Where(Directory.Exists));
    }

    private static IEnumerable<string> ResolveDeepTargets(AppSettings settings,
        DataVanger.Engine.DeepScanLayerConfig config)
    {
        var up = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var app = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var pdata = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        var targets = new List<string>();
        void Add(string p) { if (!string.IsNullOrWhiteSpace(p)) targets.Add(p); }

        // FASE 5: Restore full-drive enumeration as default for Deep profile
        // This restores the previous behavior where Deep scans enumerate the entire filesystem.
        // RemoveContainedPaths() will deduplicate these with the layered targets below.
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (!drive.IsReady) continue;
                if (drive.DriveType == DriveType.Fixed)
                    Add(drive.RootDirectory.FullName);  // C:\, D:\, E:\, etc.
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        // User folders layer
        if (config.IncludeUserFolders)
        {
            Add(Path.Combine(up, "Downloads"));
            Add(Path.Combine(up, "Desktop"));
            Add(Path.Combine(up, "Documents"));
            Add(app);
            Add(local);
            Add(Path.GetTempPath());
        }

        // System areas layer
        if (config.IncludeSystemAreas)
        {
            // C:\Windows\Temp is a system temp area, not a per-user folder, so it
            // belongs here — keeping it out of the user-folders layer lets the
            // UserFoldersOnly preset stay strictly inside the user profile.
            Add(Path.Combine(windir, "Temp"));
            Add(Path.Combine(app, @"Microsoft\Windows\Start Menu\Programs\Startup"));
            Add(Path.Combine(pdata, @"Microsoft\Windows\Start Menu\Programs\Startup"));
            Add(Path.Combine(windir, "Tasks"));
            Add(Path.Combine(windir, "System32", "Tasks"));
            Add(Path.Combine(windir, "System32", "drivers"));
            Add(pdata);
        }

        // Program Files layer
        if (config.IncludeProgramFiles)
        {
            Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        }

        // Browser extensions layer
        if (config.AnalyzeBrowserExtensions)
        {
            foreach (var browserPath in GetBrowserExtensionRoots())
                Add(browserPath);
        }

        // Removable drives layer
        if (config.IncludeRemovableDrives && settings.IncludeRemovableDrives)
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                try
                {
                    if (!drive.IsReady) continue;
                    if (drive.DriveType == DriveType.Removable)
                        Add(drive.RootDirectory.FullName);
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }

        foreach (var extra in settings.ExtraTargets.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            try { Add(Environment.ExpandEnvironmentVariables(extra)); }
            catch (Exception) { }
        }

        return RemoveContainedPaths(targets.Where(Directory.Exists));
    }

    /// <summary>
    /// Beta 10 — canonical prefix-subsumption deduplication. Normalizes every
    /// target with <see cref="Path.GetFullPath(string)"/>, drops exact duplicates
    /// (case-insensitive), and then removes any target that is the same as, or a
    /// descendant of, another retained target. This eliminates the redundant
    /// double-walk that occurred when a broad root (e.g. <c>C:\</c>) and one of its
    /// own sub-folders (e.g. <c>C:\Users\…\Downloads</c>) were both present.
    ///
    /// Safety: this never drops coverage — every file under a removed descendant is
    /// still enumerated through its retained ancestor. Containment is matched on a
    /// directory-separator boundary so <c>C:\Users</c> does not subsume
    /// <c>C:\UsersData</c>.
    /// </summary>
    public static List<string> RemoveContainedPaths(IEnumerable<string> paths)
    {
        var normalized = new List<string>();
        foreach (var p in paths)
        {
            if (string.IsNullOrWhiteSpace(p)) continue;
            try { normalized.Add(Path.GetFullPath(p)); }
            catch (Exception)
            {
                // Malformed path - skip it rather than abort target resolution.
            }
        }

        // Process shortest first so any ancestor is retained before its descendants.
        var distinct = normalized
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(p => p.Length)
            .ToList();

        var kept = new List<string>();
        foreach (var candidate in distinct)
        {
            bool contained = false;
            foreach (var ancestor in kept)
            {
                if (IsSameOrUnder(candidate, ancestor)) { contained = true; break; }
            }
            if (!contained) kept.Add(candidate);
        }
        return kept;
    }

    private static bool IsSameOrUnder(string child, string ancestor)
    {
        if (string.Equals(child, ancestor, StringComparison.OrdinalIgnoreCase)) return true;
        string prefix = ancestor.EndsWith(Path.DirectorySeparatorChar) || ancestor.EndsWith(Path.AltDirectorySeparatorChar)
            ? ancestor
            : ancestor + Path.DirectorySeparatorChar;
        return child.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    public static IEnumerable<string> GetBrowserExtensionRoots()
    {
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string app = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        yield return Path.Combine(local, @"Google\Chrome\User Data\Default\Extensions");
        yield return Path.Combine(local, @"Microsoft\Edge\User Data\Default\Extensions");
        yield return Path.Combine(local, @"BraveSoftware\Brave-Browser\User Data\Default\Extensions");
        yield return Path.Combine(app, @"Opera Software\Opera Stable\Extensions");
        yield return Path.Combine(app, @"Mozilla\Firefox\Profiles");
    }

    // DataVanger's own signature data (the seeded user signature root and the
    // app-bundled Signatures.default folder) must never be a scan target: the
    // lightweight YARA engine matches by substring, so scanning a rule file could
    // self-match, and these are product data, not user content.
    private static readonly string _signatureRootLower = ComputeSignatureRootLower();

    private static string ComputeSignatureRootLower()
    {
        try
        {
            var root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "DataVanger", "Signatures");
            return root.ToLowerInvariant().TrimEnd('\\') + "\\";
        }
        catch (Exception) { return ""; }
    }

    private static bool IsProductSignatureData(string fullLower) =>
        fullLower.Contains("\\signatures.default\\")
        || (!string.IsNullOrEmpty(_signatureRootLower) && fullLower.StartsWith(_signatureRootLower, StringComparison.Ordinal));

    public static bool IsExcludedPath(string fullLower, AppSettings settings)
    {
        if (IsProductSignatureData(fullLower)) return true;

        foreach (var raw in settings.ExcludedPaths.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            try
            {
                var ex = Path.GetFullPath(Environment.ExpandEnvironmentVariables(raw)).ToLowerInvariant().TrimEnd('\\') + "\\";
                var test = fullLower.EndsWith("\\") ? fullLower : fullLower + (Directory.Exists(fullLower) ? "\\" : "");
                if (test.StartsWith(ex) || fullLower == ex.TrimEnd('\\')) return true;
            }
            catch (Exception)
            {
                // Malformed exclusion path / environment expansion failure - treat as non-match and continue.
            }
        }
        return false;
    }
}
