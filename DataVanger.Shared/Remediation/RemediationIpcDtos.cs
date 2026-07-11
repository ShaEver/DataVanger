using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Remediation;

/// <summary>
/// Transport-only remediation action names exposed over IPC. This enum mirrors
/// the service contract without referencing engine types.
/// </summary>
public enum RemediationIpcActionKind
{
    Unknown = 0,
    KillProcessTree,
    QuarantineFile,
    DisablePersistence,
    StopAndDisableService,
    RemoveRegistryAutorun,
    RemoveScheduledTask,
    RemoveStartupFolderEntry,
    DeleteFile,
    HandleLockedFile,
    RemoveBrowserExtension,
    CleanDroppedPayload,
    RestoreHijackedSetting,
    PostRemediationVerification,
}

/// <summary>Transport-only remediation target kind names.</summary>
public enum RemediationIpcTargetKind
{
    Unknown = 0,
    File,
    Process,
    Service,
    RegistryValue,
    ScheduledTask,
    StartupEntry,
    BrowserExtension,
    SystemSetting,
}

/// <summary>
/// Transport threat band supplied by the service/UI boundary. Unknown is an
/// explicit fail-closed value so default/unset payloads are not treated as Clean.
/// </summary>
public enum RemediationIpcThreatBand
{
    Unknown = 0,
    Clean,
    Suspect,
    HighRisk,
    ConfirmedMalware,
}

/// <summary>Transport-only confirmation tier carried by consent tokens.</summary>
public enum RemediationIpcConfirmationTier
{
    Unknown = 0,
    None,
    UserConfirmation,
    RebootConsent,
    AdvancedConfirmation,
}

public enum RemediationIpcAuthorization
{
    Unknown = 0,
    Authorized,
    DeniedByPolicy,
    ConsentMissing,
    ConsentMismatch,
    ConsentExpired,
    ConsentTierInsufficient,
    ConsentTierMismatch,
}

public enum RemediationIpcPolicyOutcome
{
    Unknown = 0,
    Blocked,
    ReportOnly,
    NoAction,
    Allowed,
}

/// <summary>
/// Legacy transport shape for UI consent echo. The service does not trust this
/// object for authorization; execution consent must be issued and retained in
/// server-side remediation context.
/// </summary>
public sealed record RemediationConsentTokenDto
{
    public RemediationIpcActionKind Action { get; init; } = RemediationIpcActionKind.Unknown;
    public RemediationIpcTargetKind TargetKind { get; init; } = RemediationIpcTargetKind.Unknown;
    public string TargetIdentity { get; init; } = string.Empty;
    public RemediationIpcConfirmationTier Tier { get; init; } = RemediationIpcConfirmationTier.Unknown;
    public string CorrelationId { get; init; } = string.Empty;
    public DateTimeOffset IssuedUtc { get; init; }
    public DateTimeOffset ExpiresUtc { get; init; }
}

/// <summary>
/// Request to execute one remediation action through the service. The service
/// owns all translation to policy/execution models and must fail closed on
/// unknown actions, targets, missing server context, or missing authorization.
/// Classification/evidence/consent fields are retained for wire compatibility
/// only; they are not authoritative for authorization.
/// </summary>
public sealed record RemediationExecutionRequestDto
{
    public string CorrelationId { get; init; } = string.Empty;
    public RemediationIpcActionKind Action { get; init; } = RemediationIpcActionKind.Unknown;
    public RemediationIpcTargetKind TargetKind { get; init; } = RemediationIpcTargetKind.Unknown;
    public string TargetIdentity { get; init; } = string.Empty;

    /// <summary>Client-supplied legacy echo; ignored for execution authorization.</summary>
    public RemediationIpcThreatBand ThreatBand { get; init; } = RemediationIpcThreatBand.Unknown;

    /// <summary>Client-supplied legacy echo; ignored for execution authorization.</summary>
    public bool HasConfirmedEvidence { get; init; }

    /// <summary>Client-supplied legacy echo; ignored for execution authorization.</summary>
    public bool EvidenceIsHeuristicOnly { get; init; }

    /// <summary>Client-supplied legacy echo; ignored for execution authorization.</summary>
    public bool IsSystemFile { get; init; }

    /// <summary>Client-supplied legacy echo; ignored for execution authorization.</summary>
    public RemediationConsentTokenDto? Consent { get; init; }
}

public sealed record RemediationActionExecutionResultDto
{
    public RemediationIpcActionKind Action { get; init; } = RemediationIpcActionKind.Unknown;
    public RemediationIpcTargetKind TargetKind { get; init; } = RemediationIpcTargetKind.Unknown;
    public string TargetIdentity { get; init; } = string.Empty;
    public string Outcome { get; init; } = string.Empty;
    public bool Succeeded { get; init; }
    public bool NoChange { get; init; }
    public string Reason { get; init; } = string.Empty;
}

public sealed record RemediationExecutionResponseDto
{
    public string CorrelationId { get; init; } = string.Empty;
    public bool Authorized { get; init; }
    public RemediationIpcAuthorization Authorization { get; init; } = RemediationIpcAuthorization.Unknown;
    public RemediationIpcPolicyOutcome PolicyOutcome { get; init; } = RemediationIpcPolicyOutcome.Unknown;
    public RemediationIpcConfirmationTier RequiredConfirmation { get; init; } = RemediationIpcConfirmationTier.Unknown;
    public string DenialReason { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
    public bool RequiresReboot { get; init; }
    public bool RequiresVerification { get; init; }
    public IReadOnlyList<RemediationActionExecutionResultDto> Actions { get; init; } =
        Array.Empty<RemediationActionExecutionResultDto>();
}
