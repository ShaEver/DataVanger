using System;
using DataVanger.Core;

namespace DataVanger.Scheduling.Models;

/// <summary>
/// User-authored description of a scheduled scan. The scheduler treats it
/// as immutable while a run is in flight — mutation must go through
/// <see cref="ScanScheduler"/> so persisted state stays consistent.
/// </summary>
public sealed class ScheduledJobDefinition
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "Scheduled scan";
    public ScanProfile Profile { get; set; } = ScanProfile.Deep;
    public bool Enabled { get; set; } = true;

    public ScheduleTrigger Trigger { get; set; } = new();
    public RetryPolicy Retry { get; set; } = RetryPolicy.NoRetry;
    public MissedRunPolicy MissedRun { get; set; } = MissedRunPolicy.Skip;

    /// <summary>Optional override of the scanned path.</summary>
    public string? Target { get; set; }

    public string ReportFormat { get; set; } = "all";
}
