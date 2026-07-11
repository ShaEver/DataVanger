using System;
using System.Collections.Generic;

namespace DataVanger.Scheduling.Models;

public sealed class SchedulerJobStatusSnapshot
{
    public string JobId { get; set; } = "";
    public string Name { get; set; } = "";
    public bool Enabled { get; set; }
    public bool IsRunning { get; set; }
    public DateTime? NextRunUtc { get; set; }
    public DateTime? LastRunUtc { get; set; }
    public JobRunOutcome LastOutcome { get; set; }
    public int ConsecutiveFailures { get; set; }
}

public sealed class SchedulerStatus
{
    public bool Paused { get; set; }
    public DateTime SnapshotUtc { get; set; }
    public List<SchedulerJobStatusSnapshot> Jobs { get; set; } = new();
}
