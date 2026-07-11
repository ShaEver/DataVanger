namespace DataVanger.Engine.Remediation;

/// <summary>
/// Ordered remediation phases. The numeric order is load-bearing: a plan must
/// run in non-decreasing phase order so that the threat is neutralized and
/// contained (e.g. quarantined) BEFORE anything destructive happens, and
/// verification runs last. The plan validator enforces this ordering.
/// </summary>
public enum RemediationPhase
{
    /// <summary>Stop the threat from acting (e.g. kill a process tree).</summary>
    Neutralize = 1,

    /// <summary>Preserve evidence and make safe — quarantine, disable persistence.</summary>
    Contain = 2,

    /// <summary>Destructive removal — only after containment.</summary>
    Remove = 3,

    /// <summary>Restore a hijacked setting to a known-safe value.</summary>
    RestoreSettings = 4,

    /// <summary>Non-destructive post-remediation verification.</summary>
    Verify = 5,
}

/// <summary>Privilege required to perform an action. <see cref="Unspecified"/>
/// (0) is the invalid default so a descriptor cannot omit it.</summary>
public enum RemediationPrivilegeRequirement
{
    Unspecified = 0,
    User,
    Administrator,
    System,
}

/// <summary>Risk of performing an action. <see cref="Unspecified"/> (0) is the
/// invalid default: an action must never silently default to low risk.</summary>
public enum RemediationRiskLevel
{
    Unspecified = 0,
    None,
    Low,
    Medium,
    High,
}

/// <summary>
/// Whether an action requires a reboot to complete. Modeling this is required
/// even though phase 03A never queues a reboot.
/// </summary>
public enum RebootRequirement
{
    None = 0,
    Recommended,
    Required,
}

/// <summary>
/// Confirmation a remediation action requires before it may run. This is DATA
/// carried by the action descriptor — never an ad-hoc UI decision.
/// <see cref="Unspecified"/> (0) is the invalid default: any destructive-intent
/// action whose confirmation is Unspecified is rejected by validation.
/// </summary>
public enum ConfirmationRequirement
{
    Unspecified = 0,

    /// <summary>No confirmation needed (only valid for non-destructive actions
    /// such as verification).</summary>
    None,

    /// <summary>A normal user confirmation.</summary>
    UserConfirmation,

    /// <summary>A second, explicit confirmation for system-scope changes.</summary>
    AdvancedConfirmation,

    /// <summary>Explicit consent to a reboot-completed removal.</summary>
    RebootConsent,
}
