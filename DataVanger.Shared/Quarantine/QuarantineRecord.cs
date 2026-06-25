using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Quarantine;

/// <summary>
/// Versioned, integrity-protected quarantine record (Secure Quarantine V2).
///
/// The record is metadata only. It never contains the (decrypted) file
/// content, encryption keys, or any secret. The encrypted payload lives in a
/// separate authenticated payload file; the record's authenticity is protected
/// by a separate metadata authentication tag stored alongside it
/// (<see cref="QuarantineStoredRecord"/>).
///
/// Anti-FP note: <see cref="ThreatClassification"/> is a label captured at the
/// time of quarantine for auditability. It carries no authority — the
/// quarantine service never escalates it into ConfirmedMalware.
/// </summary>
public sealed class QuarantineRecord
{
    /// <summary>Current on-disk schema version for V2 records.</summary>
    public const int CurrentSchemaVersion = 2;

    public string QuarantineId { get; set; } = string.Empty;
    public int SchemaVersion { get; set; } = CurrentSchemaVersion;

    public string OriginalPath { get; set; } = string.Empty;
    public string OriginalFileName { get; set; } = string.Empty;
    public string OriginalExtension { get; set; } = string.Empty;
    public long OriginalSize { get; set; }

    /// <summary>SHA-256 (hex, lowercase) of the original file, computed before quarantine.</summary>
    public string OriginalSha256 { get; set; } = string.Empty;

    /// <summary>Store-relative name of the encrypted payload (never the original filename).</summary>
    public string PayloadName { get; set; } = string.Empty;

    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset? LastVerifiedUtc { get; set; }

    public string DetectionSummary { get; set; } = string.Empty;
    public QuarantineThreatClassification ThreatClassification { get; set; } = QuarantineThreatClassification.Clean;
    public List<string> EvidenceIds { get; set; } = new();
    public string SourceModule { get; set; } = string.Empty;
    public QuarantineRequestedAction RequestedAction { get; set; } = QuarantineRequestedAction.Quarantine;
    public string ActionReason { get; set; } = string.Empty;

    public QuarantineRecordState RecordState { get; set; } = QuarantineRecordState.Created;
    public int RestoreCount { get; set; }

    /// <summary>True when the original file was successfully removed/neutralized after storage.</summary>
    public bool OriginalRemoved { get; set; }

    public string PayloadEncryptionAlgorithm { get; set; } = string.Empty;
    public string PayloadAuthenticationAlgorithm { get; set; } = string.Empty;
    public string MetadataIntegrityAlgorithm { get; set; } = string.Empty;
    public QuarantineKeyProtectionMode KeyProtectionMode { get; set; } = QuarantineKeyProtectionMode.InMemory;

    public QuarantineRecord Clone()
    {
        return new QuarantineRecord
        {
            QuarantineId = QuarantineId,
            SchemaVersion = SchemaVersion,
            OriginalPath = OriginalPath,
            OriginalFileName = OriginalFileName,
            OriginalExtension = OriginalExtension,
            OriginalSize = OriginalSize,
            OriginalSha256 = OriginalSha256,
            PayloadName = PayloadName,
            CreatedUtc = CreatedUtc,
            LastVerifiedUtc = LastVerifiedUtc,
            DetectionSummary = DetectionSummary,
            ThreatClassification = ThreatClassification,
            EvidenceIds = new List<string>(EvidenceIds),
            SourceModule = SourceModule,
            RequestedAction = RequestedAction,
            ActionReason = ActionReason,
            RecordState = RecordState,
            RestoreCount = RestoreCount,
            OriginalRemoved = OriginalRemoved,
            PayloadEncryptionAlgorithm = PayloadEncryptionAlgorithm,
            PayloadAuthenticationAlgorithm = PayloadAuthenticationAlgorithm,
            MetadataIntegrityAlgorithm = MetadataIntegrityAlgorithm,
            KeyProtectionMode = KeyProtectionMode,
        };
    }
}

/// <summary>
/// The exact canonical bytes and metadata authentication tag read back from a
/// store. The service verifies the tag over <see cref="CanonicalMetadata"/>
/// BEFORE deserializing/trusting the record, so metadata tampering is detected
/// without ever acting on unauthenticated data.
/// </summary>
public sealed class QuarantineStoredRecord
{
    public QuarantineStoredRecord(byte[] canonicalMetadata, byte[] metadataTag, string metadataIntegrityAlgorithm)
    {
        CanonicalMetadata = canonicalMetadata;
        MetadataTag = metadataTag;
        MetadataIntegrityAlgorithm = metadataIntegrityAlgorithm;
    }

    /// <summary>The exact UTF-8 bytes that <see cref="MetadataTag"/> authenticates.</summary>
    public byte[] CanonicalMetadata { get; }

    public byte[] MetadataTag { get; }

    public string MetadataIntegrityAlgorithm { get; }
}

/// <summary>Projection of a record for listing/reporting. Carries no secrets.</summary>
public sealed class QuarantineIndexEntry
{
    public string QuarantineId { get; set; } = string.Empty;
    public string OriginalFileName { get; set; } = string.Empty;
    public string OriginalSha256 { get; set; } = string.Empty;
    public DateTimeOffset CreatedUtc { get; set; }
    public QuarantineRecordState RecordState { get; set; }
    public QuarantineThreatClassification ThreatClassification { get; set; }
}
