using System;
using System.Collections.Generic;
using System.Linq;
using DataVanger.Core;

namespace DataVanger.Reporting.Forensics;

/// <summary>
/// Top-level forensic report — the explainable counterpart of the raw
/// scan output produced by <see cref="DataVanger.Core.ReportGenerator"/>.
///
/// The report is intentionally serialisation-friendly (plain getters,
/// no behaviour, no IO). All interpretation is performed up-front by
/// <see cref="ForensicReportBuilder"/> so that exporters
/// (<see cref="ForensicReportExporter"/>) can render the report without
/// re-deriving severity, confidence or mitigation reasoning.
/// </summary>
public sealed class ForensicReport
{
    public ForensicReport(
        ForensicReportMetadata metadata,
        ForensicReportSummary summary,
        IReadOnlyList<Incident> incidents,
        IReadOnlyList<EvidenceChain> evidenceChains,
        ForensicTimeline timeline)
    {
        Metadata = metadata ?? new ForensicReportMetadata();
        Summary = summary ?? new ForensicReportSummary();
        Incidents = incidents ?? Array.Empty<Incident>();
        EvidenceChains = evidenceChains ?? Array.Empty<EvidenceChain>();
        Timeline = timeline ?? new ForensicTimeline();
    }

    public ForensicReportMetadata Metadata { get; }
    public ForensicReportSummary Summary { get; }
    public IReadOnlyList<Incident> Incidents { get; }
    public IReadOnlyList<EvidenceChain> EvidenceChains { get; }
    public ForensicTimeline Timeline { get; }

    /// <summary>
    /// Convenience: incidents whose severity is at least <paramref name="minimum"/>.
    /// </summary>
    public IEnumerable<Incident> IncidentsAtLeast(ForensicSeverity minimum) =>
        Incidents.Where(i => i.Severity >= minimum);
}

public sealed class ForensicReportMetadata
{
    public string ReportId { get; set; } = Guid.NewGuid().ToString("N");
    public string ScanId { get; set; } = "";
    public string EngineVersion { get; set; } = VersionInfo.FullVersion;
    public ScanProfile Profile { get; set; } = ScanProfile.Deep;
    public DateTime ScanStartedUtc { get; set; }
    public DateTime ScanCompletedUtc { get; set; }
    public string HostName { get; set; } = "";

    public TimeSpan Duration =>
        ScanCompletedUtc >= ScanStartedUtc ? ScanCompletedUtc - ScanStartedUtc : TimeSpan.Zero;
}

public sealed class ForensicReportSummary
{
    public int FindingsTotal { get; set; }
    public int FindingsConfirmedMalware { get; set; }
    public int FindingsHighRisk { get; set; }
    public int FindingsSuspect { get; set; }
    public int FindingsClean { get; set; }
    public int IncidentsTotal { get; set; }
    public int IncidentsConfirmed { get; set; }
    public int IncidentsWithMitigations { get; set; }
    public int TimelineEventsTotal { get; set; }
    public int BehavioralEventsConsumed { get; set; }
    public int MemoryFindingsConsumed { get; set; }
    public int RuntimeEventsConsumed { get; set; }
    public int SchedulerExecutionsConsumed { get; set; }
    public ForensicSeverity HighestSeverity { get; set; } = ForensicSeverity.Informational;
    public ForensicConfidence HighestConfidence { get; set; } = ForensicConfidence.Heuristic;
}
