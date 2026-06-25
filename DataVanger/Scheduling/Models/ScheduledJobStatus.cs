using System;

namespace DataVanger.Scheduling.Models;

/// <summary>
/// Volatile per-job runtime state. Persisted alongside the definition so
/// retry counters and last/next-run anchors survive restarts.
/// </summary>
public sealed class ScheduledJobStatus
{
    public string JobId { get; set; } = "";
    public DateTime? LastRunUtc { get; set; }
    public DateTime? NextRunUtc { get; set; }
    public JobRunOutcome LastOutcome { get; set; } = JobRunOutcome.NotRun;
    public string LastMessage { get; set; } = "";
    public int ConsecutiveFailures { get; set; }
    public int PendingRetryAttempt { get; set; }
    public DateTime? PendingRetryUtc { get; set; }
    public bool IsRunning { get; set; }
}
