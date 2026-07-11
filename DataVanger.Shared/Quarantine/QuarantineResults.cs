namespace DataVanger.Shared.Quarantine;

/// <summary>Structured result of a quarantine (store) operation.</summary>
public sealed class QuarantineResult
{
    public QuarantineStatus Status { get; init; } = QuarantineStatus.Unknown;
    public string? QuarantineId { get; init; }
    public QuarantineRecord? Record { get; init; }
    public string Message { get; init; } = string.Empty;

    /// <summary>
    /// True when the encrypted payload was stored and verified. Note this can be
    /// true even if <see cref="OriginalDeleteFailed"/> is also true: the threat
    /// is safely captured, but the original could not be removed.
    /// </summary>
    public bool IsStored => Status == QuarantineStatus.Success;

    /// <summary>Set when storage succeeded but the original file could not be deleted.</summary>
    public bool OriginalDeleteFailed { get; init; }

    public static QuarantineResult Failure(QuarantineStatus status, string message, string? id = null)
        => new() { Status = status, Message = message, QuarantineId = id };

    public static QuarantineResult Stored(QuarantineRecord record, bool originalDeleteFailed, string message)
        => new()
        {
            Status = QuarantineStatus.Success,
            QuarantineId = record.QuarantineId,
            Record = record,
            OriginalDeleteFailed = originalDeleteFailed,
            Message = message,
        };
}

/// <summary>Structured result of a restore operation.</summary>
public sealed class QuarantineRestoreResult
{
    public QuarantineStatus Status { get; init; } = QuarantineStatus.Unknown;
    public string? QuarantineId { get; init; }
    public string? RestoredPath { get; init; }
    public QuarantineRecord? Record { get; init; }
    public string Message { get; init; } = string.Empty;

    public bool IsRestored => Status == QuarantineStatus.Success;

    public static QuarantineRestoreResult Failure(QuarantineStatus status, string message, string? id = null, QuarantineRecord? record = null)
        => new() { Status = status, Message = message, QuarantineId = id, Record = record };

    public static QuarantineRestoreResult Restored(QuarantineRecord record, string restoredPath, string message)
        => new()
        {
            Status = QuarantineStatus.Success,
            QuarantineId = record.QuarantineId,
            RestoredPath = restoredPath,
            Record = record,
            Message = message,
        };
}

/// <summary>Structured result of an integrity verification.</summary>
public sealed class QuarantineIntegrityResult
{
    public QuarantineStatus Status { get; init; } = QuarantineStatus.Unknown;
    public string QuarantineId { get; init; } = string.Empty;
    public bool MetadataIntact { get; init; }
    public bool PayloadIntact { get; init; }
    public QuarantineRecordState RecordState { get; init; }
    public string Message { get; init; } = string.Empty;

    public bool IsIntact => Status == QuarantineStatus.Success && MetadataIntact && PayloadIntact;
}
