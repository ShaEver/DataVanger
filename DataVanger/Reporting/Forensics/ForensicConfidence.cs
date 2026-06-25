namespace DataVanger.Reporting.Forensics;

/// <summary>
/// Confidence band assigned to a forensic incident/evidence chain.
///
/// Separate from <see cref="DataVanger.Core.Domain.DetectionConfidence"/> so
/// the report layer can compose it from multiple module-level
/// confidences (signature confidence + behavioral confidence + memory
/// confidence + …) without leaking implementation details to callers.
/// </summary>
public enum ForensicConfidence
{
    Heuristic = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Confirmed = 4,
}
