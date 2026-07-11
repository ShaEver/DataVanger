using System;

namespace DataVanger.Reporting.Forensics;

/// <summary>
/// Single entry in a <see cref="ForensicTimeline"/>.
///
/// Timeline events are normalised from heterogeneous sources (deep scan,
/// behavioural engine, runtime telemetry, memory scanner, scheduler) into
/// the same compact, immutable shape so the report layer doesn't need to
/// know about every module's bespoke event types.
///
/// Anti-FP contract: timeline events are descriptive, not classifying.
/// Constructing a <see cref="TimelineEvent"/> never changes a verdict or
/// triggers quarantine.
/// </summary>
public sealed class TimelineEvent
{
    public TimelineEvent(
        DateTime timestampUtc,
        string sourceModule,
        string category,
        string description,
        int processId = 0,
        string processName = "",
        ForensicSeverity severity = ForensicSeverity.Informational,
        string correlationId = "")
    {
        TimestampUtc = timestampUtc == default
            ? DateTime.UtcNow
            : timestampUtc.ToUniversalTime();
        SourceModule = sourceModule ?? "";
        Category = category ?? "";
        Description = description ?? "";
        ProcessId = processId;
        ProcessName = processName ?? "";
        Severity = severity;
        CorrelationId = correlationId ?? "";
    }

    public DateTime TimestampUtc { get; }
    public string SourceModule { get; }
    public string Category { get; }
    public string Description { get; }
    public int ProcessId { get; }
    public string ProcessName { get; }
    public ForensicSeverity Severity { get; }
    public string CorrelationId { get; }

    public override string ToString()
    {
        string proc = ProcessId <= 0
            ? ""
            : $" pid={ProcessId}{(string.IsNullOrEmpty(ProcessName) ? "" : $" {ProcessName}")}";
        return $"[{TimestampUtc:O}] {SourceModule}:{Category}{proc} :: {Description}";
    }
}
