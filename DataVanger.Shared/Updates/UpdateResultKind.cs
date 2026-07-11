namespace DataVanger.Shared.Updates;

/// <summary>
/// Structured outcome of a verification, downgrade, or apply operation.
///
/// IMPORTANT (anti-FP guarantee): NONE of these values is a malware
/// verdict. A rejected/invalid/failed update is an operational result —
/// it never implies ConfirmedMalware, never triggers quarantine, and
/// never kills a process.
/// </summary>
public enum UpdateResultKind
{
    None = 0,

    /// <summary>Manifest passed signature + schema verification.</summary>
    Accepted = 1,

    /// <summary>New update set staged and committed successfully.</summary>
    Applied = 2,

    /// <summary>
    /// Equal sequence with an identical canonical hash: the already-installed
    /// set is current. Treated as an idempotent success.
    /// </summary>
    AlreadyCurrent = 3,

    /// <summary>Update activity is disabled by policy.</summary>
    Disabled = 4,

    /// <summary>Manifest carried no signature (missing/empty value).</summary>
    ManifestUnsigned = 5,

    /// <summary>Signature value did not verify against the pinned key.</summary>
    SignatureInvalid = 6,

    /// <summary>Signature key identifier is not pinned/known.</summary>
    UnknownKey = 7,

    /// <summary>Signature algorithm identifier is not supported.</summary>
    UnsupportedAlgorithm = 8,

    /// <summary>Manifest is missing required schema fields.</summary>
    ManifestMalformed = 9,

    /// <summary>Canonical payload could not be reconstructed safely.</summary>
    CanonicalizationFailed = 10,

    /// <summary>A required package was not available from the transport.</summary>
    PackageMissing = 11,

    /// <summary>Package content SHA-256 did not match the manifest entry.</summary>
    PackageHashMismatch = 12,

    /// <summary>Package content exceeded the configured size limit.</summary>
    PackageOversized = 13,

    /// <summary>Package relative path was unsafe (traversal/absolute/UNC).</summary>
    PackagePathRejected = 14,

    /// <summary>Package kind was unknown or not allowed by policy.</summary>
    PackageKindRejected = 15,

    /// <summary>Sequence lower than the installed highest (anti-downgrade).</summary>
    DowngradeRejected = 16,

    /// <summary>Equal sequence but a different canonical hash.</summary>
    SequenceConflict = 17,

    /// <summary>Staging/commit failed; previous active set is preserved.</summary>
    StagingFailed = 18,

    /// <summary>Rollback to last-known-good completed.</summary>
    RollbackCompleted = 19,

    /// <summary>Rollback requested but no last-known-good snapshot exists.</summary>
    NoRollbackAvailable = 20,

    /// <summary>Transport could not supply the manifest.</summary>
    TransportUnavailable = 21,

    /// <summary>Unexpected, contained failure (returned as a structured result).</summary>
    Failed = 22,
}
