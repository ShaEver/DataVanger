namespace DataVanger.Shared.RuntimeEvents;

/// <summary>
/// Severity of a runtime security event for routing, log filtering,
/// drop-policy prioritization, and UI surfacing.
///
/// IMPORTANT (anti-FP guarantee):
///   Runtime event severity is NOT a malware classification.
///   A <see cref="Critical"/> runtime event does NOT mean ConfirmedMalware.
///   ConfirmedMalware MUST originate from the existing scan engine and
///   classification policy. The pipeline never escalates verdicts.
/// </summary>
public enum RuntimeEventSeverity
{
    Informational = 0,
    Low,
    Medium,
    High,
    Critical,
}
