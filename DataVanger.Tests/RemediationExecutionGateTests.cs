using System;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Policy;
using DataVanger.Shared.Quarantine;
using Xunit;

// Phase 04 — service-side enforcement gate. A handler MUST call the gate; a
// UI-supplied unsafe or unconsented request is rejected here regardless of intent.
public class RemediationExecutionGateTests
{
    private static readonly RemediationExecutionGate Gate = new();
    private static readonly DateTimeOffset Now = new(2026, 6, 13, 12, 0, 0, TimeSpan.Zero);
    private static readonly RemediationCorrelationId CorrelationId = RemediationCorrelationId.New();
    private const string Target = "file:c:\\temp\\evil.exe";

    private static RemediationPolicyRequest Req(RemediationActionKind action, QuarantineThreatClassification band, bool confirmed)
        => new() { CorrelationId = CorrelationId, Action = action, ThreatBand = band, HasConfirmedEvidence = confirmed };

    // ── Policy denial is enforced at the gate ───────────────────────────────

    [Fact]
    public void Gate_DeniesAction_ThatPolicyBlocks_EvenWithAConsentToken()
    {
        // HighRisk delete is policy-blocked. A (spoofed) consent token must not help.
        var consent = RemediationConsentToken.Issue(
            RemediationActionKind.DeleteFile, Target, ConfirmationRequirement.AdvancedConfirmation,
            CorrelationId, Now, TimeSpan.FromMinutes(5));

        var result = Gate.Authorize(Req(RemediationActionKind.DeleteFile, QuarantineThreatClassification.HighRisk, false), Target, consent, Now);

        Assert.Equal(RemediationAuthorization.DeniedByPolicy, result.Authorization);
        Assert.False(result.IsAuthorized);
    }

    [Fact]
    public void Gate_DeniesSuspect()
    {
        var result = Gate.Authorize(Req(RemediationActionKind.QuarantineFile, QuarantineThreatClassification.Suspect, false), Target, null, Now);
        Assert.Equal(RemediationAuthorization.DeniedByPolicy, result.Authorization);
    }

    // ── Automatic actions need no consent ───────────────────────────────────

    [Fact]
    public void Gate_Authorizes_AutomaticQuarantine_WithoutConsent()
    {
        var result = Gate.Authorize(Req(RemediationActionKind.QuarantineFile, QuarantineThreatClassification.ConfirmedMalware, true), Target, null, Now);
        Assert.Equal(RemediationAuthorization.Authorized, result.Authorization);
        Assert.True(result.Decision.IsAutomatic);
        Assert.NotNull(result.Permit);
        Assert.Equal(CorrelationId, result.Permit.CorrelationId);
        Assert.Equal(RemediationActionKind.QuarantineFile, result.Permit.Action);
        Assert.Equal(Target, result.Permit.TargetMatchKey);
    }

    // ── Consent enforcement for destructive removals ────────────────────────

    [Fact]
    public void Gate_RejectsDestructiveRemoval_WithoutConsent()
    {
        var result = Gate.Authorize(Req(RemediationActionKind.DeleteFile, QuarantineThreatClassification.ConfirmedMalware, true), Target, null, Now);
        Assert.Equal(RemediationAuthorization.ConsentMissing, result.Authorization);
    }

    [Fact]
    public void Gate_Authorizes_WithMatchingValidConsent()
    {
        var consent = RemediationConsentToken.Issue(
            RemediationActionKind.DeleteFile, Target, ConfirmationRequirement.UserConfirmation,
            CorrelationId, Now, TimeSpan.FromMinutes(5));

        var result = Gate.Authorize(Req(RemediationActionKind.DeleteFile, QuarantineThreatClassification.ConfirmedMalware, true), Target, consent, Now);

        Assert.Equal(RemediationAuthorization.Authorized, result.Authorization);
        Assert.NotNull(result.Permit);
        Assert.Equal(CorrelationId, result.Permit.CorrelationId);
    }

    [Fact]
    public void Gate_RejectsConsent_ForDifferentAction()
    {
        var consent = RemediationConsentToken.Issue(
            RemediationActionKind.KillProcessTree, Target, ConfirmationRequirement.UserConfirmation,
            CorrelationId, Now, TimeSpan.FromMinutes(5));

        var result = Gate.Authorize(Req(RemediationActionKind.DeleteFile, QuarantineThreatClassification.ConfirmedMalware, true), Target, consent, Now);

        Assert.Equal(RemediationAuthorization.ConsentMismatch, result.Authorization);
    }

    [Fact]
    public void Gate_RejectsConsent_ForDifferentTarget()
    {
        var consent = RemediationConsentToken.Issue(
            RemediationActionKind.DeleteFile, "file:c:\\temp\\OTHER.exe", ConfirmationRequirement.UserConfirmation,
            CorrelationId, Now, TimeSpan.FromMinutes(5));

        var result = Gate.Authorize(Req(RemediationActionKind.DeleteFile, QuarantineThreatClassification.ConfirmedMalware, true), Target, consent, Now);

        Assert.Equal(RemediationAuthorization.ConsentMismatch, result.Authorization);
    }

    [Fact]
    public void Gate_RejectsConsent_ForDifferentCorrelation()
    {
        var consent = RemediationConsentToken.Issue(
            RemediationActionKind.DeleteFile, Target, ConfirmationRequirement.UserConfirmation,
            RemediationCorrelationId.New(), Now, TimeSpan.FromMinutes(5));

        var result = Gate.Authorize(Req(RemediationActionKind.DeleteFile, QuarantineThreatClassification.ConfirmedMalware, true), Target, consent, Now);

        Assert.Equal(RemediationAuthorization.ConsentMismatch, result.Authorization);
        Assert.Null(result.Permit);
    }

    [Fact]
    public void Gate_RejectsExpiredConsent()
    {
        var consent = RemediationConsentToken.Issue(
            RemediationActionKind.DeleteFile, Target, ConfirmationRequirement.UserConfirmation,
            CorrelationId, Now, TimeSpan.FromMinutes(5));

        var later = Now + TimeSpan.FromMinutes(10);
        var result = Gate.Authorize(Req(RemediationActionKind.DeleteFile, QuarantineThreatClassification.ConfirmedMalware, true), Target, consent, later);

        Assert.Equal(RemediationAuthorization.ConsentExpired, result.Authorization);
    }

    [Fact]
    public void Gate_RejectsWeakerConsentTier_ThanRequired()
    {
        // System-scope service stop requires AdvancedConfirmation; a UserConfirmation
        // token is insufficient.
        var consent = RemediationConsentToken.Issue(
            RemediationActionKind.StopAndDisableService, "service:evilsvc", ConfirmationRequirement.UserConfirmation,
            CorrelationId, Now, TimeSpan.FromMinutes(5));

        var result = Gate.Authorize(
            Req(RemediationActionKind.StopAndDisableService, QuarantineThreatClassification.ConfirmedMalware, true),
            "service:evilsvc", consent, Now);

        Assert.Equal(RemediationAuthorization.ConsentTierInsufficient, result.Authorization);
    }

    [Fact]
    public void Gate_RejectsDifferentStrongerConsentTier_ToKeepTierBindingExact()
    {
        var consent = RemediationConsentToken.Issue(
            RemediationActionKind.DeleteFile, Target, ConfirmationRequirement.AdvancedConfirmation,
            CorrelationId, Now, TimeSpan.FromMinutes(5));

        var result = Gate.Authorize(
            Req(RemediationActionKind.DeleteFile, QuarantineThreatClassification.ConfirmedMalware, true),
            Target, consent, Now);

        Assert.Equal(RemediationAuthorization.ConsentTierMismatch, result.Authorization);
        Assert.Null(result.Permit);
    }

    [Fact]
    public void ConsentToken_CannotBeIssued_WithNoneOrUnspecifiedTier()
    {
        Assert.Throws<ArgumentException>(() => RemediationConsentToken.Issue(
            RemediationActionKind.DeleteFile, Target, ConfirmationRequirement.None,
            RemediationCorrelationId.New(), Now, TimeSpan.FromMinutes(5)));
    }
}
