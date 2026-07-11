namespace DataVanger.Shared.ProtectedFiles;

/// <summary>
/// Severity of a piece of protected-file activity evidence produced by
/// the Protected Files Activity Monitor (Phase 2 / Step 07).
///
/// CRITICAL anti-false-positive guarantee:
///   This enum intentionally tops out at
///   <see cref="ProtectedActivitySuspected"/>. There is no "Confirmed" /
///   "Malware" member. Protected-file activity evidence is evidence
///   ONLY. It can never, by itself, become ConfirmedMalware.
///   ConfirmedMalware must always originate from the existing scan engine
///   and classification policy (confirmed hash / confirmed signature),
///   never from file-activity telemetry severity.
/// </summary>
public enum ProtectedFilesActivitySeverity
{
    /// <summary>Descriptive only; no risk implied.</summary>
    Informational = 0,

    /// <summary>Low-risk activity; benign-leaning context.</summary>
    Low,

    /// <summary>Suspicious activity pattern worth surfacing for review.</summary>
    Suspicious,

    /// <summary>Strongly suspicious activity pattern (still evidence only).</summary>
    HighRisk,

    /// <summary>
    /// Strongly correlated abnormal protected-file activity. This is the
    /// top label and is STILL evidence only — it is never, by itself,
    /// ConfirmedMalware.
    /// </summary>
    ProtectedActivitySuspected,
}
