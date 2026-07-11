using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Realtime;

/// <summary>
/// Configuration for the real-time protection orchestrator. Defaults are
/// deliberately conservative and development-safe: protection is disabled
/// by default and passive mode is on, so an unconfigured deployment never
/// quarantines or blocks anything.
/// </summary>
public sealed class RealtimeProtectionOptions
{
    /// <summary>
    /// Master switch. When false, no watchers are created and no scan
    /// loop is started. Default: false (safe in development/tests).
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// When true, the orchestrator self-identifies as Development mode
    /// regardless of how it was launched. Tests force this on.
    /// </summary>
    public bool DevelopmentMode { get; init; } = true;

    /// <summary>
    /// Passive mode means: observe, scan, report — but NEVER take a
    /// destructive action (no quarantine, no file blocking). The default
    /// for this phase is true.
    /// </summary>
    public bool PassiveMode { get; init; } = true;

    /// <summary>
    /// Debounce window for coalescing rapid-fire file system events for
    /// the same normalized path into a single scan request.
    /// Recommended range: 750ms — 2000ms.
    /// </summary>
    public TimeSpan DebounceWindow { get; init; } = TimeSpan.FromMilliseconds(1000);

    /// <summary>
    /// Maximum total time the stability probe waits for a file to become
    /// readable / stable before giving up and emitting a warning.
    /// </summary>
    public TimeSpan FileStabilityTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Delay between size/timestamp samples in the stability probe.
    /// </summary>
    public TimeSpan FileStabilityPollInterval { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>
    /// Bounded queue length for pending scan requests. Overflow produces
    /// a warning event but never crashes the orchestrator.
    /// </summary>
    public int MaxQueueLength { get; init; } = 256;

    /// <summary>
    /// Maximum number of concurrent scan worker drains. Kept small in
    /// this phase to avoid stressing the host or the existing scan
    /// engine.
    /// </summary>
    public int MaxConcurrentScans { get; init; } = 1;

    /// <summary>
    /// Hard size cap above which a file is skipped from real-time
    /// scanning (it remains eligible for manual / deep scans).
    /// </summary>
    public long MaxRealtimeScanFileSizeBytes { get; init; } = 64L * 1024L * 1024L;

    /// <summary>
    /// Explicit opt-in required for automatic quarantine of
    /// ConfirmedMalware. Even when true, the decision engine still
    /// requires the existing classification policy to mark the verdict
    /// as ConfirmedMalware. Heuristic / behavioral / memory / ETW /
    /// browser-extension / reporting evidence alone CANNOT trigger
    /// automatic quarantine.
    /// </summary>
    public bool AllowAutomaticQuarantineForConfirmedMalware { get; init; } = false;

    /// <summary>
    /// Cache window during which a scan result for an unchanged file
    /// (same path + length + last-write timestamp + hash) suppresses
    /// duplicate scanning. The cache must NEVER override a known-bad
    /// hash and must invalidate on metadata change.
    /// </summary>
    public TimeSpan ScanCacheLifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Maximum number of entries in the in-memory scan cache.
    /// </summary>
    public int ScanCacheMaxEntries { get; init; } = 1024;

    public IReadOnlyList<RealtimeWatchProfile> WatchProfiles { get; init; } = Array.Empty<RealtimeWatchProfile>();

    /// <summary>
    /// Safe, fully passive, fully disabled defaults — equivalent to the
    /// constructor defaults but explicit for tests and callers that want
    /// to start from a guaranteed-safe baseline.
    /// </summary>
    public static RealtimeProtectionOptions SafeDefaults() => new();
}
