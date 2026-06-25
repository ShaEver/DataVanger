using System;
using System.Collections.Generic;
using DataVanger.Engine.Remediation.Rollback;

namespace DataVanger.Engine.Remediation;

/// <summary>
/// The complete, immutable safety description of one remediation action. Every
/// field that governs safety is mandatory: an action cannot exist without
/// declaring its phase, privilege, risk, reversibility, rollback classification,
/// confirmation requirement, reboot requirement and target.
///
/// <see cref="Validate"/> is the single gate that makes an unsafe descriptor
/// impossible to execute. The executor calls it before doing anything; a
/// descriptor that fails validation is blocked, never run.
/// </summary>
public sealed record RemediationActionDescriptor
{
    public required RemediationActionKind Kind { get; init; }
    public required RemediationPhase Phase { get; init; }
    public required RemediationTarget Target { get; init; }
    public required RemediationPrivilegeRequirement RequiredPrivilege { get; init; }
    public required RemediationRiskLevel RiskLevel { get; init; }

    /// <summary>Whether the action can be undone. Reversible actions MUST declare
    /// a non-None <see cref="RollbackKind"/>; irreversible actions MUST declare
    /// <see cref="RollbackTokenKind.None"/>.</summary>
    public required bool IsReversible { get; init; }

    /// <summary>The rollback classification. For reversible actions this is the
    /// kind of token execution must produce; for irreversible actions it is the
    /// explicit <see cref="RollbackTokenKind.None"/> classification.</summary>
    public required RollbackTokenKind RollbackKind { get; init; }

    public required ConfirmationRequirement Confirmation { get; init; }
    public required RebootRequirement Reboot { get; init; }

    /// <summary>Human-readable, non-localized intent summary for the journal.
    /// Confirmation WORDING for the UI is a later phase; this is diagnostics.</summary>
    public string Summary { get; init; } = string.Empty;

    /// <summary>
    /// True when this action mutates the system (everything except a pure
    /// verification). Destructive-intent actions carry the strictest validation.
    /// </summary>
    public bool IsDestructiveIntent => Kind != RemediationActionKind.PostRemediationVerification
                                       && Phase != RemediationPhase.Verify;

    /// <summary>
    /// Validates the descriptor's internal consistency. Returns false with a
    /// reason on any unsafe or incomplete combination. This is the construction-
    /// time guarantee that an action cannot run without complete safety metadata.
    /// </summary>
    public bool Validate(out string reason)
    {
        if (Kind == RemediationActionKind.None)
            return Fail("Action kind is unset.", out reason);
        if (!RemediationActionCatalog.IsKnown(Kind))
            return Fail($"Action kind '{Kind}' is not catalogued.", out reason);
        if (Target is null)
            return Fail("Target is unset.", out reason);
        if (RemediationActionCatalog.TargetKindOf(Kind) != Target.Kind)
            return Fail($"Target kind '{Target.Kind}' does not match the catalogued target kind for '{Kind}'.", out reason);
        if (RequiredPrivilege == RemediationPrivilegeRequirement.Unspecified)
            return Fail("Required privilege is unspecified.", out reason);
        if (RiskLevel == RemediationRiskLevel.Unspecified)
            return Fail("Risk level is unspecified (must never silently default).", out reason);

        // Reversibility ↔ rollback classification must be coherent.
        if (IsReversible && RollbackKind == RollbackTokenKind.None)
            return Fail("Reversible action must declare a non-None rollback kind.", out reason);
        if (!IsReversible && RollbackKind != RollbackTokenKind.None)
            return Fail("Irreversible action must declare rollback kind None (explicit classification).", out reason);

        // Confirmation is mandatory data for destructive-intent actions.
        if (Confirmation == ConfirmationRequirement.Unspecified)
            return Fail("Confirmation requirement is unspecified.", out reason);
        if (IsDestructiveIntent && Confirmation == ConfirmationRequirement.None)
            return Fail("Destructive-intent action cannot have confirmation None.", out reason);

        // Reboot-completed removals must carry reboot consent.
        if (Reboot == RebootRequirement.Required && Confirmation != ConfirmationRequirement.RebootConsent)
            return Fail("Reboot-required action must use RebootConsent confirmation.", out reason);

        // The descriptor's declared phase must match the kind's catalogued phase
        // so a caller cannot relabel a destructive Remove action as Verify.
        if (RemediationActionCatalog.PhaseOf(Kind) != Phase)
            return Fail($"Phase '{Phase}' does not match the catalogued phase for '{Kind}'.", out reason);

        reason = string.Empty;
        return true;

        static bool Fail(string message, out string reason)
        {
            reason = message;
            return false;
        }
    }

    public IReadOnlyList<string> Describe() => new[]
    {
        $"kind={Kind}", $"phase={Phase}", $"target={Target}",
        $"privilege={RequiredPrivilege}", $"risk={RiskLevel}",
        $"reversible={IsReversible}", $"rollback={RollbackKind}",
        $"confirm={Confirmation}", $"reboot={Reboot}",
    };
}
