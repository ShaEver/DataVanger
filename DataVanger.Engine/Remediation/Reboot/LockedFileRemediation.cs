using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Remediation.Files;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Rollback;

namespace DataVanger.Engine.Remediation.Reboot;

/// <summary>Distinct outcomes of the locked-file / reboot remediation flow.</summary>
public enum LockedFileRemediationOutcome
{
    /// <summary>The file was not locked and was quarantined + deleted normally.</summary>
    RemovedNow = 0,

    /// <summary>The file is locked; a reboot-required plan was produced (and, if
    /// consented + queued, a pending delete-on-reboot was registered).</summary>
    RebootRequired,

    /// <summary>A reboot is required but consent was not given; nothing queued.</summary>
    BlockedConsentRequired,

    /// <summary>Quarantine of the (reversible) copy failed; nothing was queued or
    /// deleted.</summary>
    BlockedQuarantineFailed,

    /// <summary>The pending delete could not be journaled; nothing was queued.</summary>
    BlockedJournalFailed,

    /// <summary>The path is unsafe; nothing was queued.</summary>
    BlockedUnsafePath,

    Failed,
}

/// <summary>Result of the locked-file remediation flow.</summary>
public sealed record LockedFileRemediationResult
{
    public required LockedFileRemediationOutcome Outcome { get; init; }
    public required RebootRequiredState RebootState { get; init; }
    public string Reason { get; init; } = string.Empty;
    public PendingOperationId? PendingOperationId { get; init; }
    public string? QuarantineId { get; init; }
    public RollbackToken? RollbackToken { get; init; }
}

/// <summary>
/// Handles a malicious file that cannot be deleted now because it is locked. The
/// flow NEVER forces a delete and NEVER reboots:
///   1. Quarantine the file first (03B) — a reversible, verified copy exists.
///   2. If the file is NOT locked, delete it normally (03B). Outcome RemovedNow.
///   3. If it IS locked, a reboot is required. Without explicit reboot consent the
///      action stops at <see cref="RebootRequiredState.Required"/> and queues
///      nothing. With consent it journals a pending operation FIRST, then hands the
///      delete to the (fake) OS seam and records it Queued — cancelable before reboot.
/// The rollback is always the quarantine restore of the copy made in step 1.
/// </summary>
public sealed class LockedFileRemediationAction
{
    private readonly FileRemediationService _fileRemediation;
    private readonly ILockedFileDetector _lockDetector;
    private readonly IPendingFileOperationProvider _pendingProvider;
    private readonly IPendingRebootOperationStore _store;
    private readonly ISafePathPolicy _safePath;
    private readonly IRemediationClock _clock;

    public LockedFileRemediationAction(
        FileRemediationService fileRemediation,
        ILockedFileDetector lockDetector,
        IPendingFileOperationProvider pendingProvider,
        IPendingRebootOperationStore store,
        ISafePathPolicy safePath,
        IRemediationClock? clock = null)
    {
        _fileRemediation = fileRemediation ?? throw new ArgumentNullException(nameof(fileRemediation));
        _lockDetector = lockDetector ?? throw new ArgumentNullException(nameof(lockDetector));
        _pendingProvider = pendingProvider ?? throw new ArgumentNullException(nameof(pendingProvider));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _safePath = safePath ?? throw new ArgumentNullException(nameof(safePath));
        _clock = clock ?? SystemRemediationClock.Instance;
    }

    public async Task<LockedFileRemediationResult> ExecuteAsync(
        FileRemediationRequest request,
        bool rebootConsentGiven,
        IRemediationJournal journal,
        RemediationCorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (journal is null) throw new ArgumentNullException(nameof(journal));

        // 1. Quarantine first — produces the reversible copy + rollback token.
        var quarantine = await _fileRemediation.QuarantineAsync(request, journal, correlationId, cancellationToken).ConfigureAwait(false);
        if (quarantine.Outcome != FileRemediationOutcome.Quarantined || quarantine.QuarantineReference is null)
        {
            return new LockedFileRemediationResult
            {
                Outcome = LockedFileRemediationOutcome.BlockedQuarantineFailed,
                RebootState = RebootRequiredState.NotRequired,
                Reason = $"Quarantine failed: {quarantine.Outcome} — {quarantine.Reason}",
            };
        }

        var path = quarantine.QuarantineReference.OriginalPath;

        // 2. Not locked → normal delete (no reboot).
        if (!_lockDetector.IsLocked(path))
        {
            var delete = await _fileRemediation.DeleteOriginalAsync(quarantine.QuarantineReference, journal, correlationId, cancellationToken).ConfigureAwait(false);
            return new LockedFileRemediationResult
            {
                Outcome = delete.Outcome == FileRemediationOutcome.OriginalDeleted ? LockedFileRemediationOutcome.RemovedNow : LockedFileRemediationOutcome.Failed,
                RebootState = RebootRequiredState.NotRequired,
                Reason = delete.Reason,
                QuarantineId = quarantine.QuarantineId,
                RollbackToken = quarantine.RollbackToken,
            };
        }

        // 3. Locked → reboot required. Consent gates the queue.
        if (!rebootConsentGiven)
        {
            return new LockedFileRemediationResult
            {
                Outcome = LockedFileRemediationOutcome.BlockedConsentRequired,
                RebootState = RebootRequiredState.Required,
                Reason = "File is locked; a restart is required to finish removal. Awaiting explicit reboot consent.",
                QuarantineId = quarantine.QuarantineId,
                RollbackToken = quarantine.RollbackToken,
            };
        }

        // Safe-path revalidation immediately before queuing.
        var safe = _safePath.Evaluate(path);
        if (!safe.IsSafe)
        {
            return new LockedFileRemediationResult
            {
                Outcome = LockedFileRemediationOutcome.BlockedUnsafePath,
                RebootState = RebootRequiredState.Required,
                Reason = safe.Reason,
                QuarantineId = quarantine.QuarantineId,
                RollbackToken = quarantine.RollbackToken,
            };
        }

        // Journal the pending operation BEFORE handing it to the OS seam.
        var opId = PendingOperationId.New();
        var now = _clock.UtcNow;
        var operation = new PendingRebootOperation
        {
            Id = opId,
            Kind = PendingOperationKind.DeleteOnReboot,
            TargetPath = path,
            CorrelationId = correlationId,
            CancelToken = opId.ToString(),
            RollbackToken = quarantine.RollbackToken,
            BeforeStateRef = $"quarantine:{quarantine.QuarantineId}",
            Status = PendingOperationStatus.Queued,
            CreatedUtc = now,
            LastUpdatedUtc = now,
        };

        journal.Append(new RemediationJournalRecord
        {
            CorrelationId = correlationId,
            StepOrder = journal.ForCorrelation(correlationId).Count,
            EntryKind = RemediationJournalEntryKind.Intent,
            ActionKind = RemediationActionKind.HandleLockedFile,
            TargetMatchKey = $"File:{path.ToLowerInvariant()}",
            TimestampUtc = now,
            RollbackKind = RollbackTokenKind.QuarantineRestore,
            BeforeStateRef = operation.BeforeStateRef,
        });

        try
        {
            _store.Add(operation);
        }
        catch (Exception ex)
        {
            return new LockedFileRemediationResult
            {
                Outcome = LockedFileRemediationOutcome.BlockedJournalFailed,
                RebootState = RebootRequiredState.Required,
                Reason = $"Pending operation could not be journaled: {ex.GetType().Name}. Nothing was queued.",
                QuarantineId = quarantine.QuarantineId,
                RollbackToken = quarantine.RollbackToken,
            };
        }

        // Only now is the (fake) OS seam asked to defer the delete.
        try
        {
            _pendingProvider.QueueDeleteOnReboot(path);
        }
        catch (Exception ex)
        {
            _store.TryTransition(opId, PendingOperationStatus.Failed, $"Pending provider failed: {ex.GetType().Name}", _clock.UtcNow);
            journal.Append(new RemediationJournalRecord
            {
                CorrelationId = correlationId,
                StepOrder = journal.ForCorrelation(correlationId).Count,
                EntryKind = RemediationJournalEntryKind.Outcome,
                ActionKind = RemediationActionKind.HandleLockedFile,
                TargetMatchKey = $"File:{path.ToLowerInvariant()}",
                TimestampUtc = _clock.UtcNow,
                RollbackKind = RollbackTokenKind.QuarantineRestore,
                Outcome = $"Failed to queue delete-on-reboot: {ex.GetType().Name}",
            });

            return new LockedFileRemediationResult
            {
                Outcome = LockedFileRemediationOutcome.Failed,
                RebootState = RebootRequiredState.Failed,
                Reason = $"Pending delete could not be queued: {ex.GetType().Name}. Nothing was reported as completed.",
                PendingOperationId = opId,
                QuarantineId = quarantine.QuarantineId,
                RollbackToken = quarantine.RollbackToken,
            };
        }

        journal.Append(new RemediationJournalRecord
        {
            CorrelationId = correlationId,
            StepOrder = journal.ForCorrelation(correlationId).Count,
            EntryKind = RemediationJournalEntryKind.Outcome,
            ActionKind = RemediationActionKind.HandleLockedFile,
            TargetMatchKey = $"File:{path.ToLowerInvariant()}",
            TimestampUtc = _clock.UtcNow,
            RollbackKind = RollbackTokenKind.QuarantineRestore,
            Outcome = "Queued delete-on-reboot",
        });

        return new LockedFileRemediationResult
        {
            Outcome = LockedFileRemediationOutcome.RebootRequired,
            RebootState = RebootRequiredState.Queued,
            Reason = "File quarantined; original queued for deletion on next restart (cancelable before reboot).",
            PendingOperationId = opId,
            QuarantineId = quarantine.QuarantineId,
            RollbackToken = quarantine.RollbackToken,
        };
    }
}
