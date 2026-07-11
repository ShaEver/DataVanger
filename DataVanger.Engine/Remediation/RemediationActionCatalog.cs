using System;
using System.Collections.Generic;
using DataVanger.Engine.Remediation.Rollback;

namespace DataVanger.Engine.Remediation;

/// <summary>
/// The single authority on what each <see cref="RemediationActionKind"/> means:
/// its phase, default privilege, risk, reversibility, rollback classification,
/// confirmation requirement, target kind, and reboot requirement.
///
/// Centralising this prevents callers from improvising unsafe metadata (e.g.
/// labelling a file delete as low-risk or reversible-without-token). The plan
/// builder produces descriptors FROM this catalog; the descriptor validator then
/// re-checks coherence, so two independent layers must agree before anything runs.
/// </summary>
public static class RemediationActionCatalog
{
    private sealed record Definition(
        RemediationPhase Phase,
        RemediationTargetKind TargetKind,
        RemediationPrivilegeRequirement Privilege,
        RemediationRiskLevel Risk,
        bool Reversible,
        RollbackTokenKind RollbackKind,
        ConfirmationRequirement Confirmation,
        RebootRequirement Reboot);

    // Note: Confirmation here is the *minimum* requirement intrinsic to the
    // action. The detection-to-action policy (phase 04) may RAISE it, never lower
    // it. Quarantine-backed reversible actions prefer UserConfirmation; system-
    // scope changes require AdvancedConfirmation; reboot removals require consent.
    private static readonly IReadOnlyDictionary<RemediationActionKind, Definition> Definitions =
        new Dictionary<RemediationActionKind, Definition>
        {
            [RemediationActionKind.KillProcessTree] = new(
                RemediationPhase.Neutralize, RemediationTargetKind.Process,
                RemediationPrivilegeRequirement.Administrator, RemediationRiskLevel.Medium,
                Reversible: false, RollbackTokenKind.None,
                ConfirmationRequirement.UserConfirmation, RebootRequirement.None),

            [RemediationActionKind.QuarantineFile] = new(
                RemediationPhase.Contain, RemediationTargetKind.File,
                RemediationPrivilegeRequirement.User, RemediationRiskLevel.Low,
                Reversible: true, RollbackTokenKind.QuarantineRestore,
                ConfirmationRequirement.UserConfirmation, RebootRequirement.None),

            [RemediationActionKind.DisablePersistence] = new(
                RemediationPhase.Contain, RemediationTargetKind.RegistryValue,
                RemediationPrivilegeRequirement.Administrator, RemediationRiskLevel.Low,
                Reversible: true, RollbackTokenKind.RegistryValueBackup,
                ConfirmationRequirement.UserConfirmation, RebootRequirement.None),

            [RemediationActionKind.StopAndDisableService] = new(
                RemediationPhase.Remove, RemediationTargetKind.Service,
                RemediationPrivilegeRequirement.Administrator, RemediationRiskLevel.High,
                Reversible: true, RollbackTokenKind.ServiceConfigBackup,
                ConfirmationRequirement.AdvancedConfirmation, RebootRequirement.None),

            [RemediationActionKind.RemoveRegistryAutorun] = new(
                RemediationPhase.Remove, RemediationTargetKind.RegistryValue,
                RemediationPrivilegeRequirement.Administrator, RemediationRiskLevel.Medium,
                Reversible: true, RollbackTokenKind.RegistryValueBackup,
                ConfirmationRequirement.UserConfirmation, RebootRequirement.None),

            [RemediationActionKind.RemoveScheduledTask] = new(
                RemediationPhase.Remove, RemediationTargetKind.ScheduledTask,
                RemediationPrivilegeRequirement.Administrator, RemediationRiskLevel.Medium,
                Reversible: true, RollbackTokenKind.ScheduledTaskExport,
                ConfirmationRequirement.UserConfirmation, RebootRequirement.None),

            [RemediationActionKind.RemoveStartupFolderEntry] = new(
                RemediationPhase.Remove, RemediationTargetKind.StartupEntry,
                RemediationPrivilegeRequirement.User, RemediationRiskLevel.Low,
                Reversible: true, RollbackTokenKind.StartupEntryBackup,
                ConfirmationRequirement.UserConfirmation, RebootRequirement.None),

            [RemediationActionKind.DeleteFile] = new(
                RemediationPhase.Remove, RemediationTargetKind.File,
                RemediationPrivilegeRequirement.User, RemediationRiskLevel.Medium,
                Reversible: true, RollbackTokenKind.QuarantineRestore,
                ConfirmationRequirement.UserConfirmation, RebootRequirement.None),

            [RemediationActionKind.HandleLockedFile] = new(
                RemediationPhase.Remove, RemediationTargetKind.File,
                RemediationPrivilegeRequirement.Administrator, RemediationRiskLevel.Medium,
                Reversible: true, RollbackTokenKind.QuarantineRestore,
                ConfirmationRequirement.RebootConsent, RebootRequirement.Required),

            [RemediationActionKind.RemoveBrowserExtension] = new(
                RemediationPhase.Remove, RemediationTargetKind.BrowserExtension,
                RemediationPrivilegeRequirement.User, RemediationRiskLevel.Medium,
                Reversible: true, RollbackTokenKind.SettingsSnapshot,
                ConfirmationRequirement.UserConfirmation, RebootRequirement.None),

            [RemediationActionKind.CleanDroppedPayload] = new(
                RemediationPhase.Remove, RemediationTargetKind.File,
                RemediationPrivilegeRequirement.User, RemediationRiskLevel.Low,
                Reversible: true, RollbackTokenKind.QuarantineRestore,
                ConfirmationRequirement.UserConfirmation, RebootRequirement.None),

            [RemediationActionKind.RestoreHijackedSetting] = new(
                RemediationPhase.RestoreSettings, RemediationTargetKind.SystemSetting,
                RemediationPrivilegeRequirement.Administrator, RemediationRiskLevel.High,
                Reversible: true, RollbackTokenKind.SettingsSnapshot,
                ConfirmationRequirement.AdvancedConfirmation, RebootRequirement.None),

            [RemediationActionKind.PostRemediationVerification] = new(
                RemediationPhase.Verify, RemediationTargetKind.File,
                RemediationPrivilegeRequirement.User, RemediationRiskLevel.None,
                Reversible: false, RollbackTokenKind.None,
                ConfirmationRequirement.None, RebootRequirement.None),
        };

    public static bool IsKnown(RemediationActionKind kind) => Definitions.ContainsKey(kind);

    public static RemediationPhase PhaseOf(RemediationActionKind kind)
        => Get(kind).Phase;

    public static RemediationTargetKind TargetKindOf(RemediationActionKind kind)
        => Get(kind).TargetKind;

    /// <summary>
    /// Builds the canonical descriptor for a kind against a concrete target.
    /// The produced descriptor always passes <see cref="RemediationActionDescriptor.Validate"/>;
    /// callers may RAISE confirmation (phase 04 policy) via <paramref name="confirmationOverride"/>
    /// but the catalog never lets them lower it.
    /// </summary>
    public static RemediationActionDescriptor CreateDescriptor(
        RemediationActionKind kind,
        RemediationTarget target,
        ConfirmationRequirement? confirmationOverride = null,
        string? summary = null)
    {
        if (target is null) throw new ArgumentNullException(nameof(target));
        var def = Get(kind);

        if (target.Kind != def.TargetKind)
            throw new ArgumentException(
                $"Target kind '{target.Kind}' does not match the catalogued target kind '{def.TargetKind}' for '{kind}'.",
                nameof(target));

        var confirmation = def.Confirmation;
        if (confirmationOverride is { } requested)
        {
            if (def.Reboot == RebootRequirement.Required && requested != ConfirmationRequirement.RebootConsent)
                throw new ArgumentException(
                    $"Confirmation override '{requested}' cannot replace explicit reboot consent for '{kind}'.",
                    nameof(confirmationOverride));
            if (IsWeaker(requested, def.Confirmation))
                throw new ArgumentException(
                    $"Confirmation override '{requested}' is weaker than the catalogued minimum '{def.Confirmation}' for '{kind}'.",
                    nameof(confirmationOverride));
            confirmation = requested;
        }

        return new RemediationActionDescriptor
        {
            Kind = kind,
            Phase = def.Phase,
            Target = target,
            RequiredPrivilege = def.Privilege,
            RiskLevel = def.Risk,
            IsReversible = def.Reversible,
            RollbackKind = def.RollbackKind,
            Confirmation = confirmation,
            Reboot = def.Reboot,
            Summary = summary ?? $"{kind} on {target}",
        };
    }

    private static Definition Get(RemediationActionKind kind)
        => Definitions.TryGetValue(kind, out var def)
            ? def
            : throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown remediation action kind.");

    /// <summary>Strength ordering for confirmation requirements (higher = stronger).</summary>
    private static int Strength(ConfirmationRequirement c) => c switch
    {
        ConfirmationRequirement.None => 0,
        ConfirmationRequirement.UserConfirmation => 1,
        ConfirmationRequirement.RebootConsent => 2,
        ConfirmationRequirement.AdvancedConfirmation => 3,
        _ => -1, // Unspecified
    };

    private static bool IsWeaker(ConfirmationRequirement candidate, ConfirmationRequirement minimum)
        => Strength(candidate) < Strength(minimum);
}
