using System.Threading;
using System.Threading.Tasks;
using DataVanger.Scheduling.Models;

namespace DataVanger.Scheduling.Abstractions;

/// <summary>
/// Result of running a single scheduled job. Severity here describes
/// EXECUTION outcome (did the scan complete?) — it never carries a
/// malware verdict. Classification of findings remains the sole
/// responsibility of <c>ThreatClassificationPolicy</c>.
/// </summary>
public sealed class ScheduledRunResult
{
    public JobRunOutcome Outcome { get; init; } = JobRunOutcome.NotRun;
    public int FindingsCount { get; init; }
    public string Message { get; init; } = "";
    public string? ReportPath { get; init; }

    public static ScheduledRunResult Skipped(string reason)
        => new() { Outcome = JobRunOutcome.Skipped, Message = reason };

    public static ScheduledRunResult Cancelled()
        => new() { Outcome = JobRunOutcome.Cancelled, Message = "Cancelled." };
}

/// <summary>
/// Bridge between the scheduler and the existing scan engine.
/// Implementations must not block the caller indefinitely and must
/// honour the cancellation token.
/// </summary>
public interface IScheduledScanRunner
{
    Task<ScheduledRunResult> RunAsync(ScheduledJobDefinition job, CancellationToken cancellationToken);
}
