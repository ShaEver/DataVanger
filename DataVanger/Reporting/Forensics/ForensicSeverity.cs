namespace DataVanger.Reporting.Forensics;

/// <summary>
/// Severity bucket used by forensic reports. Strictly explanatory — it
/// describes how the report renders a finding, not what the classifier
/// decided. Mapping back to <see cref="DataVanger.Core.Domain.ThreatClass"/>
/// is performed by <see cref="ForensicReportBuilder"/>.
///
/// Anti-FP contract: a finding can only reach
/// <see cref="ConfirmedMalware"/> if the underlying classifier already
/// returned <c>ConfirmedMalware</c>. Heuristic-only chains stop at
/// <see cref="Critical"/>.
/// </summary>
public enum ForensicSeverity
{
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
    ConfirmedMalware = 5,
}
