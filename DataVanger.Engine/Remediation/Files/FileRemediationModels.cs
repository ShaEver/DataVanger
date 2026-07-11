using DataVanger.Engine.Remediation.Rollback;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Engine.Remediation.Files;

/// <summary>
/// A request to remediate one original file. Classification is carried (never
/// derived here) so the anti-FP contract is honored: automatic quarantine of a
/// non-ConfirmedMalware file is the quarantine service's decision, not this
/// layer's.
/// </summary>
public sealed record FileRemediationRequest
{
    public required string OriginalPath { get; init; }
    public QuarantineThreatClassification Classification { get; init; } = QuarantineThreatClassification.Clean;

    /// <summary>Whether this came from an explicit user approval or an automatic
    /// pipeline decision. Forwarded to the quarantine service, which only honors
    /// automatic requests for ConfirmedMalware.</summary>
    public QuarantineRequestOrigin Origin { get; init; } = QuarantineRequestOrigin.ManualUserApproved;

    public string DetectionSummary { get; init; } = string.Empty;
    public string SourceModule { get; init; } = string.Empty;
}

/// <summary>
/// Proof that a file was quarantined AND its quarantine record verified. This
/// token is the ONLY key that unlocks original-file deletion, so a delete cannot
/// be requested before a verified quarantine exists. Its constructor is internal
/// to the engine: callers obtain it solely from a successful
/// <see cref="FileRemediationService.QuarantineAsync"/>.
/// </summary>
public sealed record VerifiedQuarantineReference
{
    internal VerifiedQuarantineReference(string quarantineId, string originalPath, string payloadName, FileHashValue quarantinedHash)
    {
        QuarantineId = quarantineId;
        OriginalPath = originalPath;
        PayloadName = payloadName;
        QuarantinedHash = quarantinedHash;
    }

    public string QuarantineId { get; }
    public string OriginalPath { get; }
    public string PayloadName { get; }

    /// <summary>The hash of the content that was actually quarantined. Original
    /// deletion re-hashes the on-disk file and refuses if it no longer matches
    /// (TOCTOU protection).</summary>
    public FileHashValue QuarantinedHash { get; }
}

/// <summary>
/// A request to delete a quarantine STORE record. It carries ONLY a quarantine
/// id — by construction it cannot reference an original filesystem path, which
/// is what keeps store cleanup distinct from original-file deletion.
/// </summary>
public sealed record QuarantineStoreDeleteRequest
{
    public required string QuarantineId { get; init; }
}

/// <summary>A request to clean a dropped temp payload. Restricted to temp roots
/// by the service.</summary>
public sealed record TempPayloadCleanupRequest
{
    public required string Path { get; init; }
}

/// <summary>The distinct outcomes of a file remediation operation. Blocked*
/// states are honest "nothing changed" results.</summary>
public enum FileRemediationOutcome
{
    Quarantined = 0,
    OriginalDeleted,
    Restored,
    StoreRecordDeleted,
    TempCleaned,

    BlockedSourceMissing,
    BlockedUnsafePath,
    BlockedReparsePath,
    BlockedQuarantineFailed,
    BlockedQuarantineUnverified,
    BlockedHashMismatch,
    BlockedNotInTemp,
    StoreRecordNotFound,
    Failed,
}

/// <summary>Structured, non-throwing result of a file remediation operation.</summary>
public sealed record FileRemediationResult
{
    public required FileRemediationOutcome Outcome { get; init; }
    public string Reason { get; init; } = string.Empty;
    public string? QuarantineId { get; init; }
    public VerifiedQuarantineReference? QuarantineReference { get; init; }
    public RollbackToken? RollbackToken { get; init; }
    public FileHashValue? ExpectedHash { get; init; }
    public FileHashValue? ObservedHash { get; init; }

    public bool IsBlockedOrFailed => Outcome
        is FileRemediationOutcome.BlockedSourceMissing
        or FileRemediationOutcome.BlockedUnsafePath
        or FileRemediationOutcome.BlockedReparsePath
        or FileRemediationOutcome.BlockedQuarantineFailed
        or FileRemediationOutcome.BlockedQuarantineUnverified
        or FileRemediationOutcome.BlockedHashMismatch
        or FileRemediationOutcome.BlockedNotInTemp
        or FileRemediationOutcome.StoreRecordNotFound
        or FileRemediationOutcome.Failed;
}
