using System.Linq;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.SystemScope;
using Xunit;

// Phase 03C — composite persistence-removal plan ordering (descriptors only; no
// execution). Relies on the 03A plan builder/validator.
public class PersistenceRemediationPlanTests
{
    [Fact]
    public void Plan_OrdersNeutralizeContainRemoveVerify_AndIsValid()
    {
        var plan = PersistenceRemovalPlan.Build(
            processPid: "1000",
            registryAutorunIdentity: @"HKCU\...\Run\EvilApp",
            payloadPath: @"C:\Temp\evil.exe");

        Assert.True(plan.Validate(out var reason), reason);

        var phases = plan.Steps.Select(s => s.Action.Phase).ToArray();
        // Non-decreasing phase order, neutralize first, verify last.
        Assert.Equal(RemediationPhase.Neutralize, phases.First());
        Assert.Equal(RemediationPhase.Verify, phases.Last());
        for (int i = 1; i < phases.Length; i++)
            Assert.True(phases[i] >= phases[i - 1], "phases must be non-decreasing");
    }

    [Fact]
    public void Plan_PlacesPersistenceDisableAndQuarantine_BeforeDestructiveRemoval()
    {
        var plan = PersistenceRemovalPlan.Build("1000", @"HKCU\...\Run\EvilApp", @"C:\Temp\evil.exe");

        int disableIdx = IndexOf(plan, RemediationActionKind.DisablePersistence);
        int quarantineIdx = IndexOf(plan, RemediationActionKind.QuarantineFile);
        int removeRegIdx = IndexOf(plan, RemediationActionKind.RemoveRegistryAutorun);
        int deleteIdx = IndexOf(plan, RemediationActionKind.DeleteFile);

        Assert.True(disableIdx < removeRegIdx, "persistence disable must precede autorun removal");
        Assert.True(quarantineIdx < deleteIdx, "quarantine must precede file deletion");
    }

    private static int IndexOf(global::DataVanger.Engine.Remediation.Planning.RemediationPlan plan, RemediationActionKind kind)
    {
        for (int i = 0; i < plan.Steps.Count; i++)
            if (plan.Steps[i].Action.Kind == kind) return i;
        return -1;
    }
}
