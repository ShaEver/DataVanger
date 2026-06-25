using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Policy;
using DataVanger.Shared.Quarantine;
using Xunit;

// Phase 04 — anti-false-positive preservation at the policy layer. These prove
// the policy re-encodes (never weakens) the anti-FP contract: unconfirmed
// evidence can never reach the confirmed destructive path, and heuristic-only /
// system-file rules block destruction.
public class RemediationPolicyAntiFalsePositiveTests
{
    private static readonly RemediationPolicy Policy = RemediationPolicy.Instance;

    // ── Unconfirmed evidence cannot become destructive ──────────────────────

    [Fact]
    public void ConfirmedBand_WithoutConfirmedEvidence_IsConservativelyDowngraded_NoAutoQuarantine()
    {
        // A ConfirmedMalware band with HasConfirmedEvidence=false (e.g. a labeling
        // bug or unconfirmed YARA) must be treated as HighRisk: quarantine needs
        // confirmation and is NOT automatic.
        var d = Policy.Evaluate(new RemediationPolicyRequest
        {
            Action = RemediationActionKind.QuarantineFile,
            ThreatBand = QuarantineThreatClassification.ConfirmedMalware,
            HasConfirmedEvidence = false,
        });

        Assert.Equal(PolicyOutcome.Allowed, d.Outcome);
        Assert.False(d.IsAutomatic); // would have been automatic if truly confirmed
        Assert.Equal(ConfirmationRequirement.UserConfirmation, d.RequiredConfirmation);
    }

    [Fact]
    public void ConfirmedBand_WithoutConfirmedEvidence_CannotDestructivelyRemove()
    {
        var d = Policy.Evaluate(new RemediationPolicyRequest
        {
            Action = RemediationActionKind.DeleteFile,
            ThreatBand = QuarantineThreatClassification.ConfirmedMalware,
            HasConfirmedEvidence = false,
        });

        Assert.Equal(PolicyOutcome.Blocked, d.Outcome);
        Assert.Equal(PolicyDenialReason.HighRiskRequiresConfirmedMalwareForRemoval, d.DenialReason);
    }

    // ── Unconfirmed YARA specifically (Confirmed=false) ─────────────────────

    [Fact]
    public void UnconfirmedYara_RepresentedAsHighRisk_CannotKillProcess()
    {
        // Real-libyara matches emit Confirmed=false and clamp to HighRisk.
        var d = Policy.Evaluate(new RemediationPolicyRequest
        {
            Action = RemediationActionKind.KillProcessTree,
            ThreatBand = QuarantineThreatClassification.HighRisk,
            HasConfirmedEvidence = false,
        });

        Assert.Equal(PolicyOutcome.Blocked, d.Outcome);
    }

    // ── Heuristic-only evidence can never drive destruction ─────────────────

    [Fact]
    public void HeuristicOnly_BlocksDestructiveAction_EvenIfBandSomehowConfirmed()
    {
        var d = Policy.Evaluate(new RemediationPolicyRequest
        {
            Action = RemediationActionKind.DeleteFile,
            ThreatBand = QuarantineThreatClassification.ConfirmedMalware,
            HasConfirmedEvidence = true,
            EvidenceIsHeuristicOnly = true,
        });

        Assert.Equal(PolicyOutcome.Blocked, d.Outcome);
        Assert.Equal(PolicyDenialReason.HeuristicOnlyCannotRemediate, d.DenialReason);
    }

    // ── System-file protection ──────────────────────────────────────────────

    [Fact]
    public void SystemFile_HighRisk_IsBlocked()
    {
        var d = Policy.Evaluate(new RemediationPolicyRequest
        {
            Action = RemediationActionKind.DeleteFile,
            ThreatBand = QuarantineThreatClassification.HighRisk,
            HasConfirmedEvidence = false,
            IsSystemFile = true,
        });

        Assert.Equal(PolicyOutcome.Blocked, d.Outcome);
        Assert.Equal(PolicyDenialReason.SystemFileRequiresConfirmedMalware, d.DenialReason);
    }

    [Fact]
    public void SystemFile_HeuristicOnly_IsBlocked()
    {
        var d = Policy.Evaluate(new RemediationPolicyRequest
        {
            Action = RemediationActionKind.QuarantineFile,
            ThreatBand = QuarantineThreatClassification.HighRisk,
            HasConfirmedEvidence = false,
            EvidenceIsHeuristicOnly = true,
            IsSystemFile = true,
        });

        Assert.Equal(PolicyOutcome.Blocked, d.Outcome);
    }

    [Fact]
    public void SystemFile_ConfirmedMalware_AllowedButNeverAutomatic_AdvancedConfirmation()
    {
        var quarantine = Policy.Evaluate(new RemediationPolicyRequest
        {
            Action = RemediationActionKind.QuarantineFile,
            ThreatBand = QuarantineThreatClassification.ConfirmedMalware,
            HasConfirmedEvidence = true,
            IsSystemFile = true,
        });

        Assert.Equal(PolicyOutcome.Allowed, quarantine.Outcome);
        Assert.False(quarantine.IsAutomatic); // a system file is never auto-remediated
        Assert.Equal(ConfirmationRequirement.AdvancedConfirmation, quarantine.RequiredConfirmation);
    }

    // ── SystemFileGuard conservatism ────────────────────────────────────────

    [Theory]
    [InlineData("/usr/bin/evil")]
    [InlineData("/etc/passwd")]
    public void SystemFileGuard_FlagsUnixSystemRoots(string path)
        => Assert.True(new SystemFileGuard().IsSystemFile(path));

    [Fact]
    public void SystemFileGuard_NullOrUnparseable_IsConservativelySystem()
    {
        Assert.True(new SystemFileGuard().IsSystemFile(null));
        Assert.True(new SystemFileGuard().IsSystemFile("   "));
    }

    [Fact]
    public void SystemFileGuard_OrdinaryTempPath_IsNotSystem()
    {
        var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "dv-user", "evil.exe");
        Assert.False(new SystemFileGuard().IsSystemFile(path));
    }
}
