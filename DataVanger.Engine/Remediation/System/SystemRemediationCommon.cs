using System.Collections.Generic;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Rollback;

namespace DataVanger.Engine.Remediation.SystemScope;

/// <summary>
/// Distinct outcomes shared by the system-scope remediation actions (process,
/// service, registry, scheduled task, startup folder). Every "Blocked*" state is
/// an honest "nothing changed" result — the safety gate fired before any mutation.
/// </summary>
public enum SystemRemediationOutcome
{
    Succeeded = 0,

    /// <summary>Target is a protected/critical process or service.</summary>
    BlockedCriticalTarget,

    /// <summary>Target identity could not be confirmed (unknown PID/image, missing
    /// canonical service name, identity drift since plan).</summary>
    BlockedUnknownIdentity,

    /// <summary>Target does not exist.</summary>
    BlockedTargetNotFound,

    /// <summary>A required backup (registry value / service start-type) failed, so
    /// no mutation was attempted.</summary>
    BlockedBackupFailed,

    /// <summary>Scheduled-task XML export failed, so the task was not deleted.</summary>
    BlockedExportFailed,

    /// <summary>A startup item could not be quarantined, so it was not removed.</summary>
    BlockedQuarantineFailed,

    /// <summary>The target's state changed since the plan was captured.</summary>
    BlockedChangedSincePlan,

    /// <summary>No production provider is bound / the platform is unsupported.</summary>
    BlockedProviderUnavailable,

    /// <summary>The mutation itself failed (provider threw); state may be unchanged
    /// or partially changed — see the journal.</summary>
    Failed,

    RolledBack,
    RollbackFailed,
}

/// <summary>
/// Structured, non-throwing result of a system-scope remediation action. Carries
/// the rollback token (where the action is reversible), an opaque backup
/// reference, and any affected-identity detail for audit.
/// </summary>
public sealed record SystemRemediationResult
{
    public required SystemRemediationOutcome Outcome { get; init; }
    public string Reason { get; init; } = string.Empty;
    public string? TargetId { get; init; }
    public RollbackToken? RollbackToken { get; init; }
    public string? BackupRef { get; init; }
    public IReadOnlyList<string> AffectedIdentities { get; init; } = global::System.Array.Empty<string>();

    public bool Succeeded => Outcome == SystemRemediationOutcome.Succeeded;

    public bool IsBlocked => Outcome
        is SystemRemediationOutcome.BlockedCriticalTarget
        or SystemRemediationOutcome.BlockedUnknownIdentity
        or SystemRemediationOutcome.BlockedTargetNotFound
        or SystemRemediationOutcome.BlockedBackupFailed
        or SystemRemediationOutcome.BlockedExportFailed
        or SystemRemediationOutcome.BlockedQuarantineFailed
        or SystemRemediationOutcome.BlockedChangedSincePlan
        or SystemRemediationOutcome.BlockedProviderUnavailable;
}

/// <summary>
/// Shared journal helper for system-scope actions. Writes an Intent record (with
/// the captured before-state/backup reference) BEFORE any mutation, and an Outcome
/// record after — reusing the 03A append-only journal model.
/// </summary>
internal static class SystemRemediationJournal
{
    public static void Intent(
        IRemediationJournal journal,
        RemediationCorrelationId id,
        RemediationActionKind kind,
        string targetMatchKey,
        IRemediationClock clock,
        RollbackTokenKind rollbackKind,
        string? beforeStateRef)
        => journal.Append(new RemediationJournalRecord
        {
            CorrelationId = id,
            StepOrder = journal.ForCorrelation(id).Count,
            EntryKind = RemediationJournalEntryKind.Intent,
            ActionKind = kind,
            TargetMatchKey = targetMatchKey,
            TimestampUtc = clock.UtcNow,
            RollbackKind = rollbackKind,
            BeforeStateRef = beforeStateRef,
        });

    public static void Outcome(
        IRemediationJournal journal,
        RemediationCorrelationId id,
        RemediationActionKind kind,
        string targetMatchKey,
        IRemediationClock clock,
        string outcome,
        RollbackTokenKind rollbackKind = RollbackTokenKind.None)
        => journal.Append(new RemediationJournalRecord
        {
            CorrelationId = id,
            StepOrder = journal.ForCorrelation(id).Count,
            EntryKind = RemediationJournalEntryKind.Outcome,
            ActionKind = kind,
            TargetMatchKey = targetMatchKey,
            TimestampUtc = clock.UtcNow,
            RollbackKind = rollbackKind,
            Outcome = outcome,
        });
}
