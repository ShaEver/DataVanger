namespace DataVanger.Shared.Behavioral.Runtime;

/// <summary>
/// Severity of a piece of runtime behavioral evidence produced by the
/// Behavioral Engine Runtime Binding (Phase 2 / Step 06).
///
/// CRITICAL anti-false-positive guarantee:
///   This enum intentionally tops out at <see cref="HighRisk"/>. There is
///   no "Confirmed" / "Malware" member. Runtime behavioral evidence is
///   evidence ONLY. It can never, by itself, become ConfirmedMalware.
///   ConfirmedMalware must always originate from the existing scan engine
///   and classification policy (confirmed hash / confirmed signature),
///   never from behavioral telemetry severity.
/// </summary>
public enum BehavioralRuntimeSeverity
{
    /// <summary>Descriptive only; no risk implied.</summary>
    Informational = 0,

    /// <summary>Low-risk observation; benign-leaning context.</summary>
    Low,

    /// <summary>Suspicious behavior chain worth surfacing for review.</summary>
    Suspicious,

    /// <summary>
    /// Strongly suspicious behavior chain (still evidence only — never a
    /// malware verdict).
    /// </summary>
    HighRisk,
}
