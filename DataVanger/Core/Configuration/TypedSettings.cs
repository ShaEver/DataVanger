using System.Collections.Generic;

namespace DataVanger.Core.Configuration;

/// <summary>
/// Typed configuration groups.
///
/// These records expose <see cref="AppSettings"/> values as cohesive subsets
/// so each subsystem can take only the configuration it actually needs.
/// They are derived views — the persistent storage remains
/// <see cref="AppSettings"/> for backward compatibility with the existing
/// <c>appsettings.json</c> layout.
/// </summary>
public sealed record ScanSettings(
    IReadOnlyList<string> ExtraTargets,
    IReadOnlyList<string> ExcludedPaths,
    bool ScanStartupLocations,
    bool ScanDownloads,
    bool ScanDesktop,
    bool ScanDocuments,
    bool ScanAppData,
    bool IncludeRemovableDrives,
    int MinScoreToReport);

public sealed record DetectionSettings(
    bool EnableYaraRules,
    bool DeepScanArchives,
    bool AnalyzeDocuments,
    bool AnalyzeBrowserExtensions,
    bool AnalyzeAlternateDataStreams,
    bool AdvancedPersistenceChecks,
    bool AnalyzeServicesAndDrivers,
    bool AnalyzeScheduledTasks,
    int ArchiveMaxEntries,
    int ArchiveMaxDepth,
    int ArchiveMaxDecompressedMB);

public sealed record YaraSettings(
    bool Enabled,
    int MaxScanSizeMB);

public sealed record QuarantineSettings(
    bool AutoQuarantineKnownMalware,
    int MinScoreToQuarantine);

public sealed record ReputationSettings(
    bool UseSafeCache);

public sealed record ReportingSettings(
    string DefaultFormat);

public sealed record RealtimeSettings(
    bool EnableTrayProtection);

public sealed record SchedulerSettings(
    string SignatureUpdateUrl);

/// <summary>
/// Convenience projector — turns the flat <see cref="AppSettings"/> bag into
/// strongly-typed views so dependents take the smallest possible slice.
/// </summary>
public static class SettingsProjector
{
    public static ScanSettings Scan(AppSettings s) => new(
        s.ExtraTargets,
        s.ExcludedPaths,
        s.ScanStartupLocations,
        s.ScanDownloads,
        s.ScanDesktop,
        s.ScanDocuments,
        s.ScanAppData,
        s.IncludeRemovableDrives,
        s.MinScoreToReport);

    public static DetectionSettings Detection(AppSettings s) => new(
        s.EnableYaraRules,
        s.DeepScanArchives,
        s.AnalyzeDocuments,
        s.AnalyzeBrowserExtensions,
        s.AnalyzeAlternateDataStreams,
        s.AdvancedPersistenceChecks,
        s.AnalyzeServicesAndDrivers,
        s.AnalyzeScheduledTasks,
        s.ArchiveMaxEntries,
        s.ArchiveMaxDepth,
        s.ArchiveMaxDecompressedMB);

    public static YaraSettings Yara(AppSettings s) => new(s.EnableYaraRules, s.YaraMaxScanSizeMB);

    public static QuarantineSettings Quarantine(AppSettings s) =>
        new(s.AutoQuarantineKnownMalware, s.MinScoreToQuarantine);

    public static ReputationSettings Reputation(AppSettings s) => new(s.UseSafeCache);

    public static RealtimeSettings Realtime(AppSettings s) => new(s.EnableTrayProtection);

    public static SchedulerSettings Scheduler(AppSettings s) => new(s.SignatureUpdateUrl);
}
