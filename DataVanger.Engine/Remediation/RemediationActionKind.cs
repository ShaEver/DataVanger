namespace DataVanger.Engine.Remediation;

/// <summary>
/// The catalogue of remediation action kinds DataVanger may eventually perform.
///
/// IMPORTANT (phase 03A): declaring a kind here grants NO ability to perform it.
/// This phase ships only the headless domain model plus a simulation provider;
/// no kind has a real OS implementation. Whether a kind is destructive, what
/// privilege it needs, and whether it is reversible is described by
/// <see cref="RemediationActionCatalog"/> — never improvised by callers.
///
/// <see cref="None"/> is the invalid default (0) so a descriptor that forgets to
/// set a kind fails validation instead of silently meaning something.
/// </summary>
public enum RemediationActionKind
{
    None = 0,

    // ── Neutralize phase (stop the threat acting) ───────────────────────────
    KillProcessTree,

    // ── Contain phase (preserve + make safe before removal) ─────────────────
    QuarantineFile,
    DisablePersistence,

    // ── Remove phase (destructive; must follow containment) ─────────────────
    StopAndDisableService,
    RemoveRegistryAutorun,
    RemoveScheduledTask,
    RemoveStartupFolderEntry,
    DeleteFile,
    HandleLockedFile,
    RemoveBrowserExtension,
    CleanDroppedPayload,

    // ── Restore-settings phase (undo a hijack to a known-safe value) ────────
    RestoreHijackedSetting,

    // ── Verify phase (non-destructive confirmation) ─────────────────────────
    PostRemediationVerification,
}
