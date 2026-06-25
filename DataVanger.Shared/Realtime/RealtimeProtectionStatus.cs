using System;

namespace DataVanger.Shared.Realtime;

/// <summary>
/// Snapshot of real-time protection state. Always reflects whether the
/// orchestrator is Enabled, in PassiveMode, in DevelopmentMode, and how
/// many watchers are active vs. degraded. Anti-FP rule: counters and
/// state NEVER imply a malware verdict.
/// </summary>
public sealed class RealtimeProtectionStatus
{
    public bool Enabled { get; init; }
    public bool PassiveMode { get; init; }
    public bool DevelopmentMode { get; init; }

    /// <summary>
    /// Lifecycle state label: "NotStarted", "Starting", "Running",
    /// "Degraded", "Stopping", "Stopped", "Disabled".
    /// </summary>
    public string State { get; init; } = "NotStarted";

    public int ActiveWatchers { get; init; }
    public int DegradedWatchers { get; init; }

    public int PendingQueueCount { get; init; }

    public long EventsObserved { get; init; }
    public long FilesScanned { get; init; }
    public long DuplicatesSuppressed { get; init; }
    public long FilesSkipped { get; init; }
    public long Warnings { get; init; }

    public DateTimeOffset? LastEventUtc { get; init; }
    public DateTimeOffset? LastScanUtc { get; init; }
}
