using System;

namespace DataVanger.Engine.Remediation.Reboot;

/// <summary>
/// Lifecycle of a reboot-required remediation. The product can require a restart
/// to finish removing a locked artifact WITHOUT ever rebooting automatically.
///   NotRequired → the operation completed without a reboot.
///   Required    → a reboot is needed but nothing has been queued yet (awaiting consent).
///   Queued      → a pending operation was journaled and handed to the OS seam.
///   Canceled    → the user canceled before the reboot; the pending op was cleared.
///   Replayed    → after restart, the operation was applied once (idempotent).
///   Verified    → post-replay verification confirmed the artifact is gone.
///   Failed      → the operation failed; journal evidence is preserved.
/// </summary>
public enum RebootRequiredState
{
    NotRequired = 0,
    Required,
    Queued,
    Canceled,
    Replayed,
    Verified,
    Failed,
}

/// <summary>Opaque, typed id for a pending reboot operation.</summary>
public readonly record struct PendingOperationId(Guid Value)
{
    public static PendingOperationId New() => new(Guid.NewGuid());
    public bool IsEmpty => Value == Guid.Empty;
    public override string ToString() => Value.ToString("N");
}

/// <summary>The kind of OS-deferred operation. Only delete-on-reboot exists now.</summary>
public enum PendingOperationKind
{
    DeleteOnReboot = 0,
}

/// <summary>Current status of a pending operation in the durable store.</summary>
public enum PendingOperationStatus
{
    Queued = 0,
    Canceled,
    Replayed,
    Verified,
    Failed,
}

/// <summary>
/// A durable, cancelable description of an operation deferred to the next reboot.
/// It is journaled BEFORE it is handed to the OS seam, carries an explicit cancel
/// token (so it can be canceled before reboot), a correlation id, and a rollback
/// token (the quarantine restore for the already-quarantined copy).
/// </summary>
public sealed record PendingRebootOperation
{
    public required PendingOperationId Id { get; init; }
    public required PendingOperationKind Kind { get; init; }
    public required string TargetPath { get; init; }
    public required RemediationCorrelationId CorrelationId { get; init; }
    public required string CancelToken { get; init; }
    public Rollback.RollbackToken? RollbackToken { get; init; }
    public string? BeforeStateRef { get; init; }
    public PendingOperationStatus Status { get; init; } = PendingOperationStatus.Queued;
    public DateTimeOffset CreatedUtc { get; init; }
    public DateTimeOffset LastUpdatedUtc { get; init; }
}
