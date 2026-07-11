namespace DataVanger.SelfProtection;

/// <summary>
/// Severity buckets for tamper signals.
///
/// Deliberately separate from
/// <see cref="DataVanger.Core.EvidenceStrength"/> and from
/// <see cref="DataVanger.Behavioral.BehavioralSeverity"/> so the
/// Self-Protection subsystem cannot accidentally bypass the project-wide
/// anti-false-positive contract by emitting <c>Confirmed</c>.
/// </summary>
public enum TamperSeverity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}
