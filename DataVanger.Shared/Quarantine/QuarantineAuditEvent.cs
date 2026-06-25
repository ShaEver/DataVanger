using System;

namespace DataVanger.Shared.Quarantine;

/// <summary>
/// Report-safe quarantine telemetry. Audit events describe quarantine
/// operations for the runtime event pipeline, reporting, and forensics.
///
/// IMPORTANT:
///   - An audit event is telemetry. It NEVER confirms malware by itself.
///   - It carries report-safe metadata only: quarantine id, original SHA-256,
///     timestamp, classification label, operation result, record/integrity
///     state. It NEVER carries decrypted content, encryption keys, or secrets.
/// </summary>
public sealed class QuarantineAuditEvent
{
    public QuarantineAuditEventKind Kind { get; init; }
    public DateTimeOffset TimestampUtc { get; init; } = DateTimeOffset.UtcNow;

    public string? QuarantineId { get; init; }
    public string? OriginalSha256 { get; init; }
    public QuarantineThreatClassification Classification { get; init; } = QuarantineThreatClassification.Clean;

    public QuarantineStatus ResultStatus { get; init; } = QuarantineStatus.Unknown;
    public QuarantineRecordState? RecordState { get; init; }

    /// <summary>Short, secret-free human readable description.</summary>
    public string Message { get; init; } = string.Empty;
}
