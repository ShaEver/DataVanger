using System;
using System.Linq;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Policy;
using DataVanger.Shared.Quarantine;
using Xunit;

// Phase 04 — exhaustive detection-to-action policy matrix.
// Truth table (non-system file, confirmed-evidence where the band is ConfirmedMalware):
//
//   Band             | Quarantine        | Destructive removal        | System-scope        | Locked     | Verify
//   -----------------+-------------------+----------------------------+---------------------+------------+--------
//   Clean            | NoAction          | NoAction                   | NoAction            | NoAction   | NoAction
//   Suspect          | ReportOnly        | ReportOnly                 | ReportOnly          | ReportOnly | ReportOnly
//   HighRisk         | Allowed/User      | BLOCKED                    | BLOCKED             | BLOCKED    | Allowed/Auto
//   ConfirmedMalware | Allowed/Auto      | Allowed/User               | Allowed/Advanced    | Allowed/Reboot | Allowed/Auto
public class RemediationPolicyTests
{
    private static readonly RemediationPolicy Policy = RemediationPolicy.Instance;

    private static readonly RemediationActionKind[] AllActions =
        Enum.GetValues<RemediationActionKind>().Where(k => k != RemediationActionKind.None).ToArray();

    private static readonly RemediationActionKind[] DestructiveRemovals =
    {
        RemediationActionKind.DeleteFile, RemediationActionKind.CleanDroppedPayload,
        RemediationActionKind.RemoveStartupFolderEntry, RemediationActionKind.RemoveRegistryAutorun,
        RemediationActionKind.RemoveScheduledTask, RemediationActionKind.DisablePersistence,
        RemediationActionKind.KillProcessTree, RemediationActionKind.RemoveBrowserExtension,
    };

    private static RemediationPolicyDecision Eval(RemediationActionKind action, QuarantineThreatClassification band, bool confirmed)
        => Policy.Evaluate(new RemediationPolicyRequest
        {
            Action = action,
            ThreatBand = band,
            HasConfirmedEvidence = confirmed,
            EvidenceIsHeuristicOnly = false,
            IsSystemFile = false,
        });

    // ── Clean: no action for everything ─────────────────────────────────────

    [Fact]
    public void Clean_EveryAction_IsNoAction()
    {
        foreach (var action in AllActions)
        {
            var d = Eval(action, QuarantineThreatClassification.Clean, confirmed: false);
            Assert.Equal(PolicyOutcome.NoAction, d.Outcome);
            Assert.False(d.IsAllowed);
        }
    }

    // ── Suspect: report-only for everything ─────────────────────────────────

    [Fact]
    public void Suspect_EveryAction_IsReportOnly()
    {
        foreach (var action in AllActions)
        {
            var d = Eval(action, QuarantineThreatClassification.Suspect, confirmed: false);
            Assert.Equal(PolicyOutcome.ReportOnly, d.Outcome);
            Assert.False(d.IsAllowed);
        }
    }

    // ── HighRisk: quarantine-with-confirmation only; no destructive removal ──

    [Fact]
    public void HighRisk_Quarantine_RequiresUserConfirmation_NotAutomatic()
    {
        var d = Eval(RemediationActionKind.QuarantineFile, QuarantineThreatClassification.HighRisk, confirmed: false);
        Assert.Equal(PolicyOutcome.Allowed, d.Outcome);
        Assert.False(d.IsAutomatic);
        Assert.Equal(ConfirmationRequirement.UserConfirmation, d.RequiredConfirmation);
    }

    [Fact]
    public void HighRisk_EveryDestructiveRemoval_IsBlocked()
    {
        foreach (var action in DestructiveRemovals.Concat(new[]
                 {
                     RemediationActionKind.StopAndDisableService,
                     RemediationActionKind.RestoreHijackedSetting,
                     RemediationActionKind.HandleLockedFile,
                 }))
        {
            var d = Eval(action, QuarantineThreatClassification.HighRisk, confirmed: false);
            Assert.Equal(PolicyOutcome.Blocked, d.Outcome);
            Assert.Equal(PolicyDenialReason.HighRiskRequiresConfirmedMalwareForRemoval, d.DenialReason);
        }
    }

    [Fact]
    public void HighRisk_Verification_IsAutomatic()
    {
        var d = Eval(RemediationActionKind.PostRemediationVerification, QuarantineThreatClassification.HighRisk, confirmed: false);
        Assert.True(d.IsAutomatic);
    }

    // ── ConfirmedMalware: auto-quarantine; consent-gated removals ───────────

    [Fact]
    public void ConfirmedMalware_Quarantine_IsAutomatic_NoConsent()
    {
        var d = Eval(RemediationActionKind.QuarantineFile, QuarantineThreatClassification.ConfirmedMalware, confirmed: true);
        Assert.Equal(PolicyOutcome.Allowed, d.Outcome);
        Assert.True(d.IsAutomatic);
        Assert.False(d.RequiresConsent);
    }

    [Fact]
    public void ConfirmedMalware_DestructiveRemovals_RequireUserConfirmation()
    {
        foreach (var action in DestructiveRemovals)
        {
            var d = Eval(action, QuarantineThreatClassification.ConfirmedMalware, confirmed: true);
            Assert.Equal(PolicyOutcome.Allowed, d.Outcome);
            Assert.False(d.IsAutomatic);
            Assert.Equal(ConfirmationRequirement.UserConfirmation, d.RequiredConfirmation);
        }
    }

    [Theory]
    [InlineData(RemediationActionKind.StopAndDisableService)]
    [InlineData(RemediationActionKind.RestoreHijackedSetting)]
    public void ConfirmedMalware_SystemScope_RequiresAdvancedConfirmation(RemediationActionKind action)
    {
        var d = Eval(action, QuarantineThreatClassification.ConfirmedMalware, confirmed: true);
        Assert.Equal(PolicyOutcome.Allowed, d.Outcome);
        Assert.Equal(ConfirmationRequirement.AdvancedConfirmation, d.RequiredConfirmation);
    }

    [Fact]
    public void ConfirmedMalware_LockedFile_RequiresRebootConsent()
    {
        var d = Eval(RemediationActionKind.HandleLockedFile, QuarantineThreatClassification.ConfirmedMalware, confirmed: true);
        Assert.Equal(ConfirmationRequirement.RebootConsent, d.RequiredConfirmation);
    }

    // ── Completeness: every (band, action) yields a defined, fail-closed decision ──

    [Fact]
    public void EveryBandActionPair_ProducesADefinedDecision()
    {
        foreach (QuarantineThreatClassification band in Enum.GetValues<QuarantineThreatClassification>())
        foreach (var action in AllActions)
        {
            var confirmed = band == QuarantineThreatClassification.ConfirmedMalware;
            var d = Policy.Evaluate(new RemediationPolicyRequest
            {
                Action = action, ThreatBand = band, HasConfirmedEvidence = confirmed,
            });
            Assert.True(Enum.IsDefined(d.Outcome));
            // An allowed-with-consent decision must always name a real tier.
            if (d.RequiresConsent)
                Assert.NotEqual(ConfirmationRequirement.Unspecified, d.RequiredConfirmation);
        }
    }
}
