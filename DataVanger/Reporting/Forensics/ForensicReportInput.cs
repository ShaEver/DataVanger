using System;
using System.Collections.Generic;
using DataVanger.Behavioral;
using DataVanger.Core;
using DataVanger.Memory;
using DataVanger.Runtime;
using DataVanger.Scheduling.Models;

namespace DataVanger.Reporting.Forensics;

/// <summary>
/// Aggregated input for <see cref="ForensicReportBuilder"/>. Every list
/// is optional so the builder can be called with whatever subset of
/// signals a given scan produced. Module-specific code never depends on
/// this type directly — only the report layer does.
///
/// Keeping the surface as a record-of-lists (rather than wiring the
/// builder into each module) preserves the project rule that the
/// reporting subsystem must NOT redesign existing modules.
/// </summary>
public sealed class ForensicReportInput
{
    public ScanOptions Options { get; init; } = new();
    public ScanMetrics Metrics { get; init; } = new();
    public DateTime ScanStartedUtc { get; init; } = DateTime.UtcNow;
    public DateTime ScanCompletedUtc { get; init; } = DateTime.UtcNow;
    public string ScanId { get; init; } = "";
    public string HostName { get; init; } = "";

    public IReadOnlyList<ScanFinding> Findings { get; init; } = Array.Empty<ScanFinding>();
    public IReadOnlyList<BehavioralEvent> BehavioralEvents { get; init; } = Array.Empty<BehavioralEvent>();
    public IReadOnlyList<MemoryFinding> MemoryFindings { get; init; } = Array.Empty<MemoryFinding>();
    public IReadOnlyList<RuntimeTelemetryEvent> RuntimeEvents { get; init; } = Array.Empty<RuntimeTelemetryEvent>();
    public IReadOnlyList<ScheduledJobExecution> SchedulerExecutions { get; init; } = Array.Empty<ScheduledJobExecution>();
}
