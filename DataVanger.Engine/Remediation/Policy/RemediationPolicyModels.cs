using DataVanger.Shared.Quarantine;

namespace DataVanger.Engine.Remediation.Policy;

/// <summary>
/// The decision band for a remediation request. Narrower than reporting: an action
/// may be allowed automatically, allowed only with consent, allowed only as a
/// report, or denied outright.
/// </summary>
public enum PolicyOutcome
{
    /// <summary>Denied — the action must not run.</summary>
    Blocked = 0,

    /// <summary>No remediation; report/monitor only.</summary>
    ReportOnly,

    /// <summary>Clean — nothing to do.</summary>
    NoAction,

    /// <summary>Permitted (subject to <see cref="RemediationPolicyDecision.IsAutomatic"/>
    /// and the required confirmation tier).</summary>
    Allowed,
}

/// <summary>Why an action was denied / constrained — surfaced to the journal and
/// later to the UI.</summary>
public enum PolicyDenialReason
{
    None = 0,
    SuspectIsReportOnly,
    CleanIsNoAction,
    HighRiskRequiresConfirmedMalwareForRemoval,
    UnconfirmedEvidence,
    HeuristicOnlyCannotRemediate,
    SystemFileRequiresConfirmedMalware,
    SystemFileNeverAutomatic,
    UnknownClassOrAction,
}

/// <summary>
/// A request for a detection-to-action decision. Carries the classification BAND
/// (the result of the existing ThreatClassificationPolicy, mirrored by the shared
/// <see cref="QuarantineThreatClassification"/>) plus the confirmation evidence and
/// target attributes the policy needs. The policy never classifies and never
/// upgrades the band.
/// </summary>
public sealed record RemediationPolicyRequest
{
    /// <summary>The remediation run this request belongs to. The execution gate
    /// requires this when issuing execution permits or validating consent tokens,
    /// so approval for one run cannot authorize another.</summary>
    public RemediationCorrelationId CorrelationId { get; init; }

    public required RemediationActionKind Action { get; init; }
    public required QuarantineThreatClassification ThreatBand { get; init; }

    /// <summary>True only when the band is backed by CONFIRMED evidence — a
    /// known-malicious hash or a YARA rule with Confirmed=true. Real-libyara matches
    /// (Confirmed=false) and heuristics never set this.</summary>
    public bool HasConfirmedEvidence { get; init; }

    /// <summary>True when the only evidence is heuristic (no confirmation).</summary>
    public bool EvidenceIsHeuristicOnly { get; init; }

    /// <summary>True when the target is a protected system file/path.</summary>
    public bool IsSystemFile { get; init; }
}

/// <summary>
/// The authoritative decision: outcome, whether it may run automatically, the
/// required confirmation tier when consent is needed, the denial reason, and an
/// audit rationale.
/// </summary>
public sealed record RemediationPolicyDecision
{
    public required RemediationActionKind Action { get; init; }
    public required PolicyOutcome Outcome { get; init; }

    /// <summary>True only for a safe, reversible, confirmed-malware action that may
    /// run without consent (today: quarantine + post-remediation verification).</summary>
    public bool IsAutomatic { get; init; }

    /// <summary>The consent tier required when <see cref="Outcome"/> is Allowed and
    /// <see cref="IsAutomatic"/> is false.</summary>
    public ConfirmationRequirement RequiredConfirmation { get; init; } = ConfirmationRequirement.Unspecified;

    public PolicyDenialReason DenialReason { get; init; } = PolicyDenialReason.None;
    public string Rationale { get; init; } = string.Empty;

    /// <summary>True when the action may proceed at all (Allowed).</summary>
    public bool IsAllowed => Outcome == PolicyOutcome.Allowed;

    /// <summary>True when execution requires a consent token (Allowed, not automatic).</summary>
    public bool RequiresConsent => Outcome == PolicyOutcome.Allowed && !IsAutomatic;
}
