namespace DataVanger.Behavioral;

/// <summary>
/// Behavioral severity bucket. Independent from
/// <see cref="DataVanger.Core.EvidenceStrength"/> so the behavioral
/// engine can keep its own scale (and never accidentally bypass the
/// project-wide anti-FP contract by emitting <c>Confirmed</c>).
///
/// Order matters: higher values mean higher severity, so callers can
/// compare with &gt;= when filtering.
/// </summary>
public enum BehavioralSeverity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}
