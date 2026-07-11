using System;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Rollback;
using Xunit;

// Phase 03A — remediation domain model tests (action metadata + descriptor
// validation + rollback token typing + catalog authority).
// Filter: dotnet test --filter "FullyQualifiedName~Remediation".
public class RemediationCoreModelTests
{
    private static RemediationTarget File(string p = @"C:\Temp\evil.exe")
        => new(RemediationTargetKind.File, p);

    // ── Descriptor validation: every safety field is mandatory ──────────────

    [Fact]
    public void Descriptor_FromCatalog_IsValid()
    {
        var d = RemediationActionCatalog.CreateDescriptor(RemediationActionKind.QuarantineFile, File());
        Assert.True(d.Validate(out var reason), reason);
    }

    [Fact]
    public void Descriptor_UnspecifiedRisk_IsRejected()
    {
        var d = Base() with { RiskLevel = RemediationRiskLevel.Unspecified };
        Assert.False(d.Validate(out var reason));
        Assert.Contains("Risk", reason);
    }

    [Fact]
    public void Descriptor_UnspecifiedPrivilege_IsRejected()
    {
        var d = Base() with { RequiredPrivilege = RemediationPrivilegeRequirement.Unspecified };
        Assert.False(d.Validate(out var reason));
        Assert.Contains("privilege", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Descriptor_ReversibleWithoutRollbackKind_IsRejected()
    {
        var d = Base() with { IsReversible = true, RollbackKind = RollbackTokenKind.None };
        Assert.False(d.Validate(out var reason));
        Assert.Contains("Reversible", reason);
    }

    [Fact]
    public void Descriptor_IrreversibleWithRollbackKind_IsRejected()
    {
        var d = Base() with { IsReversible = false, RollbackKind = RollbackTokenKind.QuarantineRestore };
        Assert.False(d.Validate(out var reason));
        Assert.Contains("Irreversible", reason);
    }

    [Fact]
    public void Descriptor_DestructiveIntentWithConfirmationNone_IsRejected()
    {
        var d = Base() with { Confirmation = ConfirmationRequirement.None };
        Assert.False(d.Validate(out var reason));
        Assert.Contains("confirmation", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Descriptor_UnspecifiedConfirmation_IsRejected()
    {
        var d = Base() with { Confirmation = ConfirmationRequirement.Unspecified };
        Assert.False(d.Validate(out var reason));
        Assert.Contains("Confirmation", reason);
    }

    [Fact]
    public void Descriptor_RebootRequiredWithoutRebootConsent_IsRejected()
    {
        var d = Base() with { Reboot = RebootRequirement.Required, Confirmation = ConfirmationRequirement.UserConfirmation };
        Assert.False(d.Validate(out var reason));
        Assert.Contains("Reboot", reason);
    }

    [Fact]
    public void Descriptor_PhaseMismatchWithKind_IsRejected()
    {
        // QuarantineFile is a Contain action; claiming it is Remove must fail.
        var d = RemediationActionCatalog.CreateDescriptor(RemediationActionKind.QuarantineFile, File())
            with { Phase = RemediationPhase.Remove };
        Assert.False(d.Validate(out var reason));
        Assert.Contains("Phase", reason);
    }

    [Fact]
    public void Descriptor_TargetKindMismatchWithKind_IsRejected()
    {
        var d = RemediationActionCatalog.CreateDescriptor(RemediationActionKind.DeleteFile, File())
            with { Target = new RemediationTarget(RemediationTargetKind.Process, "4321") };

        Assert.False(d.Validate(out var reason));
        Assert.Contains("Target kind", reason);
    }

    [Fact]
    public void Descriptor_UnknownKind_IsRejected()
    {
        var d = Base() with { Kind = (RemediationActionKind)999 };

        Assert.False(d.Validate(out var reason));
        Assert.Contains("not catalogued", reason);
    }

    // ── Catalog authority: known kinds, confirmation cannot be lowered ──────

    [Fact]
    public void Catalog_KnowsEveryDeclaredKind_ExceptNone()
    {
        foreach (RemediationActionKind kind in Enum.GetValues<RemediationActionKind>())
        {
            if (kind == RemediationActionKind.None) continue;
            Assert.True(RemediationActionCatalog.IsKnown(kind), $"Catalog missing {kind}");
        }
    }

    [Fact]
    public void Catalog_RejectsTargetKindMismatch()
    {
        Assert.Throws<ArgumentException>(() =>
            RemediationActionCatalog.CreateDescriptor(
                RemediationActionKind.KillProcessTree, File())); // process kind expects Process target
    }

    [Fact]
    public void Catalog_RejectsWeakerConfirmationOverride()
    {
        // StopAndDisableService minimum is AdvancedConfirmation; lowering to
        // UserConfirmation must be refused.
        Assert.Throws<ArgumentException>(() =>
            RemediationActionCatalog.CreateDescriptor(
                RemediationActionKind.StopAndDisableService,
                new RemediationTarget(RemediationTargetKind.Service, "EvilSvc"),
                ConfirmationRequirement.UserConfirmation));
    }

    [Fact]
    public void Catalog_AllowsStrongerConfirmationOverride()
    {
        var d = RemediationActionCatalog.CreateDescriptor(
            RemediationActionKind.QuarantineFile, File(), ConfirmationRequirement.AdvancedConfirmation);
        Assert.Equal(ConfirmationRequirement.AdvancedConfirmation, d.Confirmation);
        Assert.True(d.Validate(out _));
    }

    [Fact]
    public void Catalog_DoesNotLetAdvancedConfirmationReplaceRebootConsent()
    {
        Assert.Throws<ArgumentException>(() =>
            RemediationActionCatalog.CreateDescriptor(
                RemediationActionKind.HandleLockedFile,
                File(),
                ConfirmationRequirement.AdvancedConfirmation));
    }

    // ── Rollback token typing ───────────────────────────────────────────────

    [Fact]
    public void RollbackToken_Reversible_RequiresKindAndPayload()
    {
        var id = RemediationCorrelationId.New();
        Assert.Throws<ArgumentException>(() => RollbackToken.For(RollbackTokenKind.None, "x", id));
        Assert.Throws<ArgumentException>(() => RollbackToken.For(RollbackTokenKind.QuarantineRestore, "", id));

        var t = RollbackToken.For(RollbackTokenKind.QuarantineRestore, "qid-123", id);
        Assert.True(t.CanRollback);
        Assert.Equal(RollbackTokenKind.QuarantineRestore, t.Kind);
    }

    [Fact]
    public void RollbackToken_Irreversible_CannotRollback()
    {
        var t = RollbackToken.Irreversible(RemediationCorrelationId.New());
        Assert.False(t.CanRollback);
        Assert.Equal(RollbackTokenKind.None, t.Kind);
        Assert.Null(t.Payload);
    }

    // ── Target validation ────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Target_RejectsEmptyIdentity(string identity)
        => Assert.Throws<ArgumentException>(() => new RemediationTarget(RemediationTargetKind.File, identity));

    [Fact]
    public void Target_RejectsNoneKind()
        => Assert.Throws<ArgumentException>(() => new RemediationTarget(RemediationTargetKind.None, "x"));

    /// <summary>A valid destructive Remove descriptor used as a mutation base.</summary>
    private static RemediationActionDescriptor Base()
        => RemediationActionCatalog.CreateDescriptor(RemediationActionKind.RemoveRegistryAutorun,
            new RemediationTarget(RemediationTargetKind.RegistryValue, @"HKCU\...\Run\evil"));
}
