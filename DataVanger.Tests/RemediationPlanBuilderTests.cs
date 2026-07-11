using System;
using System.Linq;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Planning;
using Xunit;

// Phase 03A — plan ordering and safe-construction tests.
public class RemediationPlanBuilderTests
{
    private static RemediationTarget F(string p) => new(RemediationTargetKind.File, p);
    private static RemediationTarget Proc(string pid) => new(RemediationTargetKind.Process, pid);

    [Fact]
    public void Builder_OrdersStepsByPhase_NeutralizeContainRemoveVerify()
    {
        // Add out of order; builder must sort into safe phase order.
        var plan = new RemediationPlanBuilder()
            .Add(RemediationActionKind.PostRemediationVerification, F(@"C:\t\evil.exe"))
            .Add(RemediationActionKind.DeleteFile, F(@"C:\t\evil.exe"))
            .Add(RemediationActionKind.QuarantineFile, F(@"C:\t\evil.exe"))
            .Add(RemediationActionKind.KillProcessTree, Proc("1234"))
            .Build();

        var phases = plan.Steps.Select(s => s.Action.Phase).ToArray();
        Assert.Equal(new[]
        {
            RemediationPhase.Neutralize, // kill
            RemediationPhase.Contain,    // quarantine
            RemediationPhase.Remove,     // delete
            RemediationPhase.Verify,     // verification
        }, phases);

        // Step orders are re-indexed sequentially.
        Assert.Equal(new[] { 0, 1, 2, 3 }, plan.Steps.Select(s => s.Order).ToArray());
        Assert.True(plan.Validate(out var reason), reason);
    }

    [Fact]
    public void Builder_PreservesInsertionOrderWithinSamePhase()
    {
        // Two Remove-phase actions on already-quarantined files keep insertion order.
        var plan = new RemediationPlanBuilder()
            .Add(RemediationActionKind.QuarantineFile, F(@"C:\a.exe"))
            .Add(RemediationActionKind.QuarantineFile, F(@"C:\b.exe"))
            .Add(RemediationActionKind.DeleteFile, F(@"C:\a.exe"))
            .Add(RemediationActionKind.DeleteFile, F(@"C:\b.exe"))
            .Build();

        var removeTargets = plan.Steps
            .Where(s => s.Action.Phase == RemediationPhase.Remove)
            .Select(s => s.Action.Target.Identity)
            .ToArray();
        Assert.Equal(new[] { @"C:\a.exe", @"C:\b.exe" }, removeTargets);
    }

    [Fact]
    public void Builder_RejectsDeleteWithoutPrecedingQuarantine()
    {
        // A file delete with no containment for the same target must be refused.
        var builder = new RemediationPlanBuilder()
            .Add(RemediationActionKind.DeleteFile, F(@"C:\t\evil.exe"));

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("not preceded by a QuarantineFile", ex.Message);
    }

    [Fact]
    public void Builder_RejectsDeleteWhenQuarantineIsForDifferentTarget()
    {
        var builder = new RemediationPlanBuilder()
            .Add(RemediationActionKind.QuarantineFile, F(@"C:\t\other.exe"))
            .Add(RemediationActionKind.DeleteFile, F(@"C:\t\evil.exe"));

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Builder_AllowsDelete_WhenSameTargetQuarantinedFirst()
    {
        var plan = new RemediationPlanBuilder()
            .Add(RemediationActionKind.QuarantineFile, F(@"C:\t\evil.exe"))
            .Add(RemediationActionKind.DeleteFile, F(@"C:\t\evil.exe"))
            .Build();

        Assert.True(plan.Validate(out var reason), reason);
    }

    [Fact]
    public void Builder_EmptyPlan_IsRejected()
        => Assert.Throws<InvalidOperationException>(() => new RemediationPlanBuilder().Build());

    [Fact]
    public void Plan_HandWritten_OutOfPhaseOrder_FailsValidation()
    {
        // Bypass the builder to prove the plan itself rejects bad ordering:
        // a Remove step placed before its Contain step.
        var quarantine = RemediationActionCatalog.CreateDescriptor(RemediationActionKind.QuarantineFile, F(@"C:\evil.exe"));
        var delete = RemediationActionCatalog.CreateDescriptor(RemediationActionKind.DeleteFile, F(@"C:\evil.exe"));

        var plan = new RemediationPlan
        {
            CorrelationId = RemediationCorrelationId.New(),
            Steps = new[]
            {
                new RemediationPlanStep(0, delete),    // Remove first — unsafe
                new RemediationPlanStep(1, quarantine) // Contain second
            },
        };

        Assert.False(plan.Validate(out var reason));
        Assert.Contains("Out-of-order phase", reason);
    }

    [Fact]
    public void MatchKey_IsCaseInsensitive_ForFilePaths()
    {
        // Quarantine and delete differing only by case must be treated as the
        // same target so the deletion-after-quarantine rule still holds.
        var plan = new RemediationPlanBuilder()
            .Add(RemediationActionKind.QuarantineFile, F(@"C:\Temp\Evil.exe"))
            .Add(RemediationActionKind.DeleteFile, F(@"C:\temp\evil.EXE"))
            .Build();

        Assert.True(plan.Validate(out var reason), reason);
    }
}
