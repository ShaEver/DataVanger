namespace DataVanger.Shared.Quarantine;

/// <summary>
/// Lifecycle state of a versioned quarantine record (Secure Quarantine V2,
/// Phase 2 / Step 08).
///
/// Anti-FP note: none of these states is a malware verdict. A
/// <see cref="Corrupt"/> or <see cref="MissingPayload"/> state describes the
/// integrity of the quarantine store, NOT the classification of the original
/// file. Tampering with quarantine internals never produces ConfirmedMalware.
/// </summary>
public enum QuarantineRecordState
{
    Created = 0,
    Stored,
    Verified,
    RestorePending,
    Restored,
    RestoreFailed,
    Corrupt,
    MissingPayload,
    DeletedByUser,
}

/// <summary>
/// Structured outcome for every quarantine/restore/verify operation. Normal
/// operational failures are reported through this enum — they are never thrown
/// as unhandled exceptions and never escalate into a malware verdict.
/// </summary>
public enum QuarantineStatus
{
    Success = 0,
    Cancelled,
    UnsupportedPlatform,
    PolicyDenied,
    SourceMissing,
    SourceAccessDenied,
    SourceReadFailed,
    SourceTooLarge,
    SourceIdentityConflict,
    ReparsePointRejected,
    HashFailed,
    EncryptionFailed,
    AuthenticationFailed,
    MetadataWriteFailed,
    PayloadWriteFailed,
    CommitFailed,
    OriginalDeleteFailed,
    RecordNotFound,
    PayloadMissing,
    IntegrityCheckFailed,
    MetadataTampered,
    RestorePathInvalid,
    RestoreTargetExists,
    RestoreRaceConflict,
    RestoreFailed,
    Unknown,
}

/// <summary>
/// How the local quarantine key is protected at rest. Telemetry/audit value
/// only — it never contains key material.
/// </summary>
public enum QuarantineKeyProtectionMode
{
    /// <summary>Deterministic in-memory protector used by tests and non-persistent scenarios.</summary>
    InMemory = 0,

    /// <summary>Windows DPAPI (ProtectedData) — production Windows only.</summary>
    DpapiWindows,

    /// <summary>No supported protector on this platform; operations degrade gracefully.</summary>
    UnsupportedPlatform,
}

/// <summary>
/// Operational quarantine telemetry kinds. These are emitted as audit/runtime
/// events. They are telemetry only and NEVER confirm malware by themselves.
/// </summary>
public enum QuarantineAuditEventKind
{
    QuarantineRequested = 0,
    QuarantineStored,
    QuarantineVerified,
    QuarantineFailed,
    QuarantineRestoreRequested,
    QuarantineRestored,
    QuarantineRestoreFailed,
    QuarantineIntegrityFailed,
    QuarantineMetadataTamperDetected,
    QuarantinePayloadMissing,
}

/// <summary>
/// Whether a quarantine request was raised automatically by the scan/response
/// pipeline or explicitly approved by a user. Automatic requests are only
/// honored for <see cref="QuarantineThreatClassification.ConfirmedMalware"/>.
/// </summary>
public enum QuarantineRequestOrigin
{
    Automatic = 0,
    ManualUserApproved,
}

/// <summary>
/// The action a request asks the quarantine service to take. This phase only
/// implements safe, reversible storage; destructive/irreversible actions are
/// intentionally absent.
/// </summary>
public enum QuarantineRequestedAction
{
    Quarantine = 0,
    ReportOnly,
}

/// <summary>
/// Mirror of the engine's threat classification, carried on quarantine
/// requests/records for auditability. It is a label captured at the time of
/// quarantine — it has NO classification authority and the quarantine service
/// never derives or mutates a verdict from it.
/// </summary>
public enum QuarantineThreatClassification
{
    Clean = 0,
    Suspect,
    HighRisk,
    ConfirmedMalware,
}
