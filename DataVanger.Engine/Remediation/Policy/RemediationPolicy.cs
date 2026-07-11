using DataVanger.Shared.Quarantine;

namespace DataVanger.Engine.Remediation.Policy;

/// <summary>
/// The single authority that maps detection confidence to permitted remediation
/// actions. It is intentionally NARROWER than reporting and re-encodes (never
/// weakens) the anti-false-positive contract:
///
///   • ConfirmedMalware (with confirmed evidence) may AUTO-quarantine; destructive
///     removals are Allowed but require consent (system-scope → advanced; locked →
///     reboot consent).
///   • HighRisk permits user-confirmed QUARANTINE only; every destructive removal is
///     BLOCKED (it requires ConfirmedMalware). HighRisk is never automatic.
///   • Suspect is REPORT-ONLY. Clean is NO-ACTION.
///   • A ConfirmedMalware band WITHOUT confirmed evidence is conservatively treated
///     as HighRisk (defends against unconfirmed-YARA / heuristic escalation).
///   • System files may be remediated ONLY for ConfirmedMalware+confirmed evidence,
///     and never automatically (advanced confirmation). Any weaker evidence on a
///     system file is BLOCKED.
///   • Heuristic-only evidence can never drive a destructive action.
///
/// This class does NOT classify and does NOT change ThreatClassificationPolicy or
/// AntiFalsePositivePolicy; it consumes the band those produce.
/// </summary>
public sealed class RemediationPolicy
{
    public static RemediationPolicy Instance { get; } = new();

    public RemediationPolicyDecision Evaluate(RemediationPolicyRequest request)
    {
        System.ArgumentNullException.ThrowIfNull(request);

        // Conservative downgrade: a ConfirmedMalware band that is NOT backed by
        // confirmed evidence is treated as HighRisk. This is the anti-FP floor —
        // unconfirmed YARA / heuristics can never reach the confirmed destructive path.
        var band = request.ThreatBand;
        if (band == QuarantineThreatClassification.ConfirmedMalware && !request.HasConfirmedEvidence)
        {
            return EvaluateBand(request, QuarantineThreatClassification.HighRisk,
                note: "ConfirmedMalware band without confirmed evidence — treated conservatively as HighRisk.");
        }

        return EvaluateBand(request, band, note: null);
    }

    private static RemediationPolicyDecision EvaluateBand(RemediationPolicyRequest request, QuarantineThreatClassification band, string? note)
    {
        var action = request.Action;
        bool destructive = IsDestructive(action);

        // ── System-file guard (highest priority for files) ──────────────────
        if (request.IsSystemFile)
        {
            if (band != QuarantineThreatClassification.ConfirmedMalware || !request.HasConfirmedEvidence)
                return Block(action, PolicyDenialReason.SystemFileRequiresConfirmedMalware,
                    "System file may be remediated only on ConfirmedMalware with confirmed evidence.", note);

            // ConfirmedMalware + confirmed on a system file: allowed, but never
            // automatic — always advanced confirmation (even for quarantine).
            if (action == RemediationActionKind.PostRemediationVerification)
                return Auto(action, "Verification of a system-file remediation is non-destructive.", note);
            return Allow(action, ConfirmationRequirement.AdvancedConfirmation,
                "System-file remediation requires advanced confirmation.", note);
        }

        // ── Heuristic-only evidence can never drive a destructive action ────
        if (request.EvidenceIsHeuristicOnly && destructive)
            return Block(action, PolicyDenialReason.HeuristicOnlyCannotRemediate,
                "Heuristic-only evidence cannot drive a destructive action.", note);

        return band switch
        {
            QuarantineThreatClassification.Clean =>
                NoAction(action, note),

            QuarantineThreatClassification.Suspect =>
                ReportOnly(action, note),

            QuarantineThreatClassification.HighRisk =>
                EvaluateHighRisk(action, note),

            QuarantineThreatClassification.ConfirmedMalware =>
                EvaluateConfirmed(action, note),

            _ => Block(action, PolicyDenialReason.UnknownClassOrAction, "Unknown threat band; failing closed.", note),
        };
    }

    private static RemediationPolicyDecision EvaluateConfirmed(RemediationActionKind action, string? note) => action switch
    {
        // Safe + reversible → may run automatically (matches the existing
        // ConfirmedMalware-only auto-quarantine gate in QuarantineService).
        RemediationActionKind.QuarantineFile =>
            Auto(action, "ConfirmedMalware: quarantine is safe and reversible — auto-remediate.", note),
        RemediationActionKind.PostRemediationVerification =>
            Auto(action, "Post-remediation verification is non-destructive.", note),

        // Destructive but reversible removals → user consent.
        RemediationActionKind.DeleteFile or
        RemediationActionKind.CleanDroppedPayload or
        RemediationActionKind.RemoveStartupFolderEntry or
        RemediationActionKind.RemoveRegistryAutorun or
        RemediationActionKind.RemoveScheduledTask or
        RemediationActionKind.DisablePersistence or
        RemediationActionKind.KillProcessTree or
        RemediationActionKind.RemoveBrowserExtension =>
            Allow(action, ConfirmationRequirement.UserConfirmation,
                "ConfirmedMalware destructive removal requires user confirmation.", note),

        // System-scope changes → advanced confirmation.
        RemediationActionKind.StopAndDisableService or
        RemediationActionKind.RestoreHijackedSetting =>
            Allow(action, ConfirmationRequirement.AdvancedConfirmation,
                "ConfirmedMalware system-scope change requires advanced confirmation.", note),

        // Locked-file removal → reboot consent.
        RemediationActionKind.HandleLockedFile =>
            Allow(action, ConfirmationRequirement.RebootConsent,
                "Locked-file removal completes on reboot and requires reboot consent.", note),

        _ => Block(action, PolicyDenialReason.UnknownClassOrAction, "Unknown action; failing closed.", note),
    };

    private static RemediationPolicyDecision EvaluateHighRisk(RemediationActionKind action, string? note) => action switch
    {
        // HighRisk may quarantine (reversible containment) with user confirmation —
        // never automatically.
        RemediationActionKind.QuarantineFile =>
            Allow(action, ConfirmationRequirement.UserConfirmation,
                "HighRisk may be quarantined only with user confirmation.", note),
        RemediationActionKind.PostRemediationVerification =>
            Auto(action, "Verification is non-destructive.", note),

        // Every destructive removal is blocked for HighRisk — it requires
        // ConfirmedMalware. HighRisk can never auto-delete and never destructively
        // remove on unconfirmed evidence.
        _ when IsDestructive(action) =>
            Block(action, PolicyDenialReason.HighRiskRequiresConfirmedMalwareForRemoval,
                "Destructive removal requires ConfirmedMalware; HighRisk is quarantine-with-confirmation only.", note),

        _ => Block(action, PolicyDenialReason.UnknownClassOrAction, "Unknown action; failing closed.", note),
    };

    /// <summary>True for any action that mutates the system (everything except
    /// pure verification).</summary>
    public static bool IsDestructive(RemediationActionKind action)
        => action != RemediationActionKind.PostRemediationVerification;

    // ── Decision constructors ───────────────────────────────────────────────

    private static RemediationPolicyDecision Auto(RemediationActionKind action, string rationale, string? note)
        => new() { Action = action, Outcome = PolicyOutcome.Allowed, IsAutomatic = true, RequiredConfirmation = ConfirmationRequirement.None, Rationale = Join(rationale, note) };

    private static RemediationPolicyDecision Allow(RemediationActionKind action, ConfirmationRequirement tier, string rationale, string? note)
        => new() { Action = action, Outcome = PolicyOutcome.Allowed, IsAutomatic = false, RequiredConfirmation = tier, Rationale = Join(rationale, note) };

    private static RemediationPolicyDecision ReportOnly(RemediationActionKind action, string? note)
        => new() { Action = action, Outcome = PolicyOutcome.ReportOnly, DenialReason = PolicyDenialReason.SuspectIsReportOnly, Rationale = Join("Suspect is report-only.", note) };

    private static RemediationPolicyDecision NoAction(RemediationActionKind action, string? note)
        => new() { Action = action, Outcome = PolicyOutcome.NoAction, DenialReason = PolicyDenialReason.CleanIsNoAction, Rationale = Join("Clean — no action.", note) };

    private static RemediationPolicyDecision Block(RemediationActionKind action, PolicyDenialReason reason, string rationale, string? note)
        => new() { Action = action, Outcome = PolicyOutcome.Blocked, DenialReason = reason, Rationale = Join(rationale, note) };

    private static string Join(string rationale, string? note)
        => string.IsNullOrEmpty(note) ? rationale : $"{rationale} ({note})";
}
