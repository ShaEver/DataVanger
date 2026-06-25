using System;
using System.Collections.Generic;

namespace DataVanger.Shared.ProtectedFiles;

/// <summary>
/// Configuration for the Protected Files Activity Monitor (Phase 2 /
/// Step 07). Defaults are conservative and development-safe: passive,
/// bounded state, TTL cleanup, no remediation authority, no background
/// loops, entropy sampling off.
/// </summary>
public sealed class ProtectedFilesActivityOptions
{
    private static readonly IReadOnlyList<string> EmptyRoots = Array.Empty<string>();

    /// <summary>Operating mode. Every mode in this phase is passive (never acts).</summary>
    public ProtectedFilesActivityMode Mode { get; init; } = ProtectedFilesActivityMode.Development;

    /// <summary>Monitor abnormal activity in protected user folders. On by default.</summary>
    public bool EnableProtectedFolderMonitoring { get; init; } = true;

    /// <summary>
    /// Use bounded entropy delta signals when a producer supplies a
    /// pre-computed, bounded entropy value. Off by default — the monitor
    /// never reads file contents itself.
    /// </summary>
    public bool EnableEntropySampling { get; init; }

    /// <summary>Record normalized recovery-protection indicator labels. On by default.</summary>
    public bool EnableRecoveryIndicatorLabels { get; init; } = true;

    /// <summary>Correlate suspicious extension transitions on rename. On by default.</summary>
    public bool EnableExtensionTransitionAnalysis { get; init; } = true;

    /// <summary>Correlate activity by process context. On by default.</summary>
    public bool EnableProcessContextCorrelation { get; init; } = true;

    /// <summary>
    /// Whether the (passive) safe-response policy may surface an
    /// "active" recommendation label. Even when true this phase NEVER
    /// performs an active response — it is recommendation/evidence only.
    /// Off by default.
    /// </summary>
    public bool EnableActiveResponseHooks { get; init; }

    /// <summary>Sliding window over which high-volume activity is correlated.</summary>
    public TimeSpan ActivityWindow { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Modification count within <see cref="ActivityWindow"/> at/above
    /// which mutation volume becomes suspicious. Explainable threshold.
    /// </summary>
    public int ModificationBurstThreshold { get; init; } = 50;

    /// <summary>Rename count within <see cref="ActivityWindow"/> at/above which a rename burst is suspicious.</summary>
    public int RenameBurstThreshold { get; init; } = 25;

    /// <summary>Suspicious extension-transition count at/above which extension replacement is suspicious.</summary>
    public int SuspiciousExtensionTransitionThreshold { get; init; } = 8;

    /// <summary>Rate limit (fixed 1-minute window). Overflow events are dropped and counted.</summary>
    public int MaxEventsPerMinute { get; init; } = 12000;

    /// <summary>Maximum correlation keys (processes) tracked at once.</summary>
    public int MaxTrackedProcesses { get; init; } = 4096;

    /// <summary>Maximum distinct directories retained per tracked process.</summary>
    public int MaxTrackedDirectories { get; init; } = 256;

    /// <summary>Maximum distinct extension transitions retained per tracked process.</summary>
    public int MaxTrackedExtensionTransitions { get; init; } = 128;

    /// <summary>Maximum timestamps retained per activity window (memory bound).</summary>
    public int MaxWindowSamples { get; init; } = 4096;

    /// <summary>Upper bound on an advisory entropy sample size (bytes). Advisory only.</summary>
    public long MaxEntropySampleBytes { get; init; } = 64 * 1024;

    /// <summary>Time-to-live for tracked process state before TTL cleanup removes it.</summary>
    public TimeSpan ProcessStateTtl { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// When true the monitor may publish generated activity evidence back
    /// onto a runtime event pipeline (as a RansomwareSuspicion telemetry
    /// event) for reporting consumers. Default false to keep this phase
    /// isolated and to avoid any feedback loops / score inflation.
    /// </summary>
    public bool RepublishEvidenceToPipeline { get; init; }

    /// <summary>Bounded number of recent evidence items retained for snapshotting.</summary>
    public int MaxRetainedEvidence { get; init; } = 256;

    /// <summary>Bounded number of recent warnings retained for the status snapshot.</summary>
    public int MaxRetainedWarnings { get; init; } = 64;

    /// <summary>
    /// Protected folder roots (path fragments matched case-insensitively).
    /// When empty the monitor falls back to conservative built-in user
    /// folder name heuristics (Documents, Desktop, Pictures, Videos,
    /// OneDrive).
    /// </summary>
    public IReadOnlyList<string> ProtectedFolderRoots { get; init; } = EmptyRoots;

    /// <summary>
    /// Development-safe roots (path fragments) whose activity is heavily
    /// down-scored so builds/tests never trip the monitor. When empty the
    /// monitor falls back to built-in dev/build fragments (bin, obj,
    /// .git, node_modules, packages, TempTest...).
    /// </summary>
    public IReadOnlyList<string> DevelopmentSafeRoots { get; init; } = EmptyRoots;

    /// <summary>Excluded roots (path fragments) whose activity is ignored entirely for scoring.</summary>
    public IReadOnlyList<string> ExcludedRoots { get; init; } = EmptyRoots;

    /// <summary>Conservative, development-safe defaults (passive).</summary>
    public static ProtectedFilesActivityOptions DevelopmentSafe() => new()
    {
        Mode = ProtectedFilesActivityMode.Development,
    };

    /// <summary>Fully disabled monitor (wired but inert).</summary>
    public static ProtectedFilesActivityOptions Disabled() => new()
    {
        Mode = ProtectedFilesActivityMode.Disabled,
    };

    /// <summary>Passive production-style monitor (still never acts; evidence only).</summary>
    public static ProtectedFilesActivityOptions Passive() => new()
    {
        Mode = ProtectedFilesActivityMode.Passive,
    };

    /// <summary>True when the monitor should subscribe and analyze.</summary>
    public bool IsEnabled => Mode != ProtectedFilesActivityMode.Disabled;

    /// <summary>
    /// Returns a copy with values clamped into safe ranges so callers
    /// cannot accidentally disable bounding or TTL cleanup.
    /// </summary>
    public ProtectedFilesActivityOptions WithSafeDefaults()
    {
        return new ProtectedFilesActivityOptions
        {
            Mode = Mode,
            EnableProtectedFolderMonitoring = EnableProtectedFolderMonitoring,
            EnableEntropySampling = EnableEntropySampling,
            EnableRecoveryIndicatorLabels = EnableRecoveryIndicatorLabels,
            EnableExtensionTransitionAnalysis = EnableExtensionTransitionAnalysis,
            EnableProcessContextCorrelation = EnableProcessContextCorrelation,
            EnableActiveResponseHooks = EnableActiveResponseHooks,
            ActivityWindow = ClampWindow(ActivityWindow, TimeSpan.FromSeconds(30)),
            ModificationBurstThreshold = Clamp(ModificationBurstThreshold, 1, 1_000_000, 50),
            RenameBurstThreshold = Clamp(RenameBurstThreshold, 1, 1_000_000, 25),
            SuspiciousExtensionTransitionThreshold = Clamp(SuspiciousExtensionTransitionThreshold, 1, 1_000_000, 8),
            MaxEventsPerMinute = Clamp(MaxEventsPerMinute, 1, 5_000_000, 12000),
            MaxTrackedProcesses = Clamp(MaxTrackedProcesses, 1, 1_000_000, 4096),
            MaxTrackedDirectories = Clamp(MaxTrackedDirectories, 1, 100_000, 256),
            MaxTrackedExtensionTransitions = Clamp(MaxTrackedExtensionTransitions, 1, 100_000, 128),
            MaxWindowSamples = Clamp(MaxWindowSamples, 16, 1_000_000, 4096),
            MaxEntropySampleBytes = MaxEntropySampleBytes <= 0 ? 64 * 1024 : Math.Min(MaxEntropySampleBytes, 16L * 1024 * 1024),
            ProcessStateTtl = ClampWindow(ProcessStateTtl, TimeSpan.FromMinutes(10)),
            RepublishEvidenceToPipeline = RepublishEvidenceToPipeline,
            MaxRetainedEvidence = Clamp(MaxRetainedEvidence, 1, 100_000, 256),
            MaxRetainedWarnings = Clamp(MaxRetainedWarnings, 1, 4096, 64),
            ProtectedFolderRoots = ProtectedFolderRoots ?? EmptyRoots,
            DevelopmentSafeRoots = DevelopmentSafeRoots ?? EmptyRoots,
            ExcludedRoots = ExcludedRoots ?? EmptyRoots,
        };
    }

    private static int Clamp(int value, int min, int max, int fallback)
    {
        if (value <= 0) return fallback;
        if (value < min) return min;
        return value > max ? max : value;
    }

    private static TimeSpan ClampWindow(TimeSpan value, TimeSpan fallback)
    {
        if (value <= TimeSpan.Zero) return fallback;
        var max = TimeSpan.FromHours(24);
        return value > max ? max : value;
    }
}
