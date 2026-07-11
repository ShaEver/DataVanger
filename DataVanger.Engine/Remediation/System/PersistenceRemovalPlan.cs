using System;
using DataVanger.Engine.Remediation.Planning;

namespace DataVanger.Engine.Remediation.SystemScope;

/// <summary>
/// Builds a composite "disable persistence before destructive removal" plan as
/// ordered 03A descriptors. It DESCRIBES the safe order (neutralize → contain →
/// remove → verify) and relies on the 03A plan builder/validator to guarantee it;
/// it executes nothing.
///
/// The canonical order this produces:
///   1. Kill the malicious process tree (Neutralize),
///   2. Disable persistence + quarantine the payload (Contain),
///   3. Remove the autorun value, then delete the quarantined payload (Remove),
///   4. Post-remediation verification (Verify).
/// </summary>
public static class PersistenceRemovalPlan
{
    public static RemediationPlan Build(
        string processPid,
        string registryAutorunIdentity,
        string payloadPath)
    {
        if (string.IsNullOrWhiteSpace(processPid)) throw new ArgumentException("PID required.", nameof(processPid));
        if (string.IsNullOrWhiteSpace(registryAutorunIdentity)) throw new ArgumentException("Autorun identity required.", nameof(registryAutorunIdentity));
        if (string.IsNullOrWhiteSpace(payloadPath)) throw new ArgumentException("Payload path required.", nameof(payloadPath));

        return new RemediationPlanBuilder()
            .Add(RemediationActionKind.KillProcessTree, new RemediationTarget(RemediationTargetKind.Process, processPid))
            .Add(RemediationActionKind.DisablePersistence, new RemediationTarget(RemediationTargetKind.RegistryValue, registryAutorunIdentity))
            .Add(RemediationActionKind.QuarantineFile, new RemediationTarget(RemediationTargetKind.File, payloadPath))
            .Add(RemediationActionKind.RemoveRegistryAutorun, new RemediationTarget(RemediationTargetKind.RegistryValue, registryAutorunIdentity))
            .Add(RemediationActionKind.DeleteFile, new RemediationTarget(RemediationTargetKind.File, payloadPath))
            .Add(RemediationActionKind.PostRemediationVerification, new RemediationTarget(RemediationTargetKind.File, payloadPath))
            .Build();
    }
}
