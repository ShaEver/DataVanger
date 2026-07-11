using System;

namespace DataVanger.Shared.ProtectedFiles;

/// <summary>
/// Immutable health/status snapshot of the Protected Files Activity
/// Monitor (Phase 2 / Step 07). Cheap to produce, never throws, safe to
/// surface in UI later.
///
/// Anti-FP note: none of these counters are verdicts. EvidenceGenerated
/// counts protected-file activity evidence items, which are evidence
/// only.
/// </summary>
public sealed class ProtectedFilesActivityHealthSnapshot
{
    public ProtectedFilesActivityMode Mode { get; init; } = ProtectedFilesActivityMode.Disabled;

    public ProtectedFilesActivityMonitorState State { get; init; } = ProtectedFilesActivityMonitorState.Disabled;

    public bool IsEnabled { get; init; }
    public bool IsPassive { get; init; }
    public bool IsDegraded { get; init; }

    public bool ProtectedFolderMonitoringEnabled { get; init; }
    public bool EntropySamplingEnabled { get; init; }
    public bool RecoveryIndicatorLabelsEnabled { get; init; }
    public bool ActiveResponseEnabled { get; init; }

    /// <summary>Total runtime events received by the monitor consumer.</summary>
    public long EventsReceived { get; init; }

    /// <summary>Total file-activity observations created by the adapter.</summary>
    public long ObservationsCreated { get; init; }

    /// <summary>Total protected-file activity evidence items generated.</summary>
    public long EvidenceGenerated { get; init; }

    /// <summary>
    /// Total events/observations dropped (disabled, rate-limited, or shed
    /// under state pressure). Bounded by design.
    /// </summary>
    public long EventsDropped { get; init; }

    /// <summary>Number of recent alerts (evidence items recently emitted, bounded view).</summary>
    public long RecentAlertCount { get; init; }

    /// <summary>Number of correlation keys (processes) currently tracked.</summary>
    public int TrackedProcessCount { get; init; }

    /// <summary>Number of distinct directories currently tracked across all processes.</summary>
    public int TrackedDirectoryCount { get; init; }

    public string? LastWarning { get; init; }
    public string? LastError { get; init; }

    public DateTimeOffset? LastEventUtc { get; init; }
}
