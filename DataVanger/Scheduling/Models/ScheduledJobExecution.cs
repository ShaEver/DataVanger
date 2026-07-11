using System;

namespace DataVanger.Scheduling.Models;

public sealed class ScheduledJobExecution
{
    public string JobId { get; set; } = "";
    public string JobName { get; set; } = "";
    public DateTime StartedUtc { get; set; }
    public DateTime CompletedUtc { get; set; }
    public JobRunOutcome Outcome { get; set; }
    public int FindingsCount { get; set; }
    public int AttemptNumber { get; set; } = 1;
    public string Message { get; set; } = "";
    public string? ReportPath { get; set; }

    public TimeSpan Duration => CompletedUtc - StartedUtc;
}
