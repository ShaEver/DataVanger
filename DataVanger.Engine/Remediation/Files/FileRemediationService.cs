using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Rollback;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Engine.Remediation.Files;

/// <summary>
/// The first real destructive-remediation capability: safe file remediation that
/// preserves DataVanger's quarantine-first trust model.
///
/// Guarantees enforced here (by construction, not convention):
///   - QUARANTINE BEFORE DELETE: the only way to delete an original file is to
///     pass a <see cref="VerifiedQuarantineReference"/>, which can ONLY be
///     produced by a successful, verified quarantine. There is no delete-by-path.
///   - HASH VERIFICATION: deletion re-hashes the on-disk file immediately before
///     deleting and refuses if it no longer matches what was quarantined (TOCTOU
///     protection).
///   - SAFE PATH: system/program roots, reparse points, traversal, ADS, and
///     non-absolute paths are refused.
///   - STORE DELETE IS DISTINCT: <see cref="DeleteQuarantineStoreRecordAsync"/>
///     takes only a quarantine id and removes the encrypted payload; it can never
///     receive a filesystem path, so it cannot delete an original file.
///   - ROLLBACK THROUGH QUARANTINE: restore delegates to the unchanged quarantine
///     service, preserving its strong warnings and integrity checks.
///
/// It never classifies and never weakens anti-FP: classification is carried from
/// the caller into the quarantine service, which alone decides automatic-vs-manual
/// honoring (automatic only for ConfirmedMalware).
/// </summary>
public sealed class FileRemediationService
{
    private readonly IQuarantineRemediationGateway _quarantine;
    private readonly IQuarantineStoreCleanup _storeCleanup;
    private readonly IFileHashProvider _hash;
    private readonly ISafePathPolicy _safePath;
    private readonly IFileSystemRemediationOperations _fs;
    private readonly IRemediationClock _clock;

    public FileRemediationService(
        IQuarantineRemediationGateway quarantine,
        IQuarantineStoreCleanup storeCleanup,
        IFileHashProvider hash,
        ISafePathPolicy safePath,
        IFileSystemRemediationOperations fs,
        IRemediationClock? clock = null)
    {
        _quarantine = quarantine ?? throw new ArgumentNullException(nameof(quarantine));
        _storeCleanup = storeCleanup ?? throw new ArgumentNullException(nameof(storeCleanup));
        _hash = hash ?? throw new ArgumentNullException(nameof(hash));
        _safePath = safePath ?? throw new ArgumentNullException(nameof(safePath));
        _fs = fs ?? throw new ArgumentNullException(nameof(fs));
        _clock = clock ?? SystemRemediationClock.Instance;
    }

    /// <summary>
    /// Quarantines an original file and verifies the resulting record. Does NOT
    /// delete the original. On success returns a <see cref="VerifiedQuarantineReference"/>
    /// — the only key that unlocks deletion.
    /// </summary>
    public async Task<FileRemediationResult> QuarantineAsync(
        FileRemediationRequest request,
        IRemediationJournal journal,
        RemediationCorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (journal is null) throw new ArgumentNullException(nameof(journal));

        var safe = _safePath.Evaluate(request.OriginalPath);
        if (!safe.IsSafe)
            return Blocked(FileRemediationOutcome.BlockedUnsafePath, safe.Reason);

        if (!_fs.Exists(request.OriginalPath))
            return Blocked(FileRemediationOutcome.BlockedSourceMissing, "Original file does not exist.");

        if (_fs.IsReparsePoint(request.OriginalPath))
            return Blocked(FileRemediationOutcome.BlockedReparsePath, "Original path is a reparse point/symlink.");

        FileHashValue expected = await _hash.ComputeAsync(request.OriginalPath, cancellationToken).ConfigureAwait(false);

        AppendIntent(journal, correlationId, RemediationActionKind.QuarantineFile, request.OriginalPath, RollbackTokenKind.QuarantineRestore, expected.ToString());

        var quarantineResult = await _quarantine.QuarantineAsync(new QuarantineRequest
        {
            SourcePath = request.OriginalPath,
            Classification = request.Classification,
            Origin = request.Origin,
            RequestedAction = QuarantineRequestedAction.Quarantine,
            DetectionSummary = request.DetectionSummary,
            SourceModule = request.SourceModule,
            DeleteOriginalAfterStore = false, // remediation owns deletion (with re-hash) — never the store path
        }, cancellationToken).ConfigureAwait(false);

        if (!quarantineResult.IsStored || quarantineResult.QuarantineId is null)
        {
            AppendOutcome(journal, correlationId, RemediationActionKind.QuarantineFile, request.OriginalPath, $"BlockedQuarantineFailed: {quarantineResult.Status}");
            return Blocked(FileRemediationOutcome.BlockedQuarantineFailed, $"Quarantine failed: {quarantineResult.Status} — {quarantineResult.Message}");
        }

        var integrity = await _quarantine.VerifyAsync(quarantineResult.QuarantineId, cancellationToken).ConfigureAwait(false);
        if (!integrity.IsIntact)
        {
            AppendOutcome(journal, correlationId, RemediationActionKind.QuarantineFile, request.OriginalPath, $"BlockedQuarantineUnverified: {integrity.Status}");
            return Blocked(FileRemediationOutcome.BlockedQuarantineUnverified, $"Quarantine record could not be verified: {integrity.Status} — {integrity.Message}");
        }

        var record = await _quarantine.GetAsync(quarantineResult.QuarantineId, cancellationToken).ConfigureAwait(false);
        if (record is null)
        {
            AppendOutcome(journal, correlationId, RemediationActionKind.QuarantineFile, request.OriginalPath, "BlockedQuarantineUnverified: record vanished");
            return Blocked(FileRemediationOutcome.BlockedQuarantineUnverified, "Quarantine record could not be read after verification.");
        }

        var quarantinedHash = new FileHashValue(record.OriginalSha256, "SHA-256");
        if (!expected.Matches(quarantinedHash))
        {
            AppendOutcome(journal, correlationId, RemediationActionKind.QuarantineFile, request.OriginalPath, "BlockedHashMismatch: record hash differs from pre-quarantine hash");
            return new FileRemediationResult
            {
                Outcome = FileRemediationOutcome.BlockedHashMismatch,
                Reason = "Quarantine record hash differs from the pre-quarantine file hash; refusing to produce a verified delete reference.",
                QuarantineId = record.QuarantineId,
                ExpectedHash = expected,
                ObservedHash = quarantinedHash,
            };
        }

        var reference = new VerifiedQuarantineReference(record.QuarantineId, record.OriginalPath, record.PayloadName, quarantinedHash);
        var token = RollbackToken.For(RollbackTokenKind.QuarantineRestore, record.QuarantineId, correlationId);

        AppendOutcome(journal, correlationId, RemediationActionKind.QuarantineFile, request.OriginalPath, "Quarantined", RollbackTokenKind.QuarantineRestore);

        return new FileRemediationResult
        {
            Outcome = FileRemediationOutcome.Quarantined,
            Reason = "File quarantined and record verified.",
            QuarantineId = record.QuarantineId,
            QuarantineReference = reference,
            RollbackToken = token,
            ExpectedHash = expected,
        };
    }

    /// <summary>
    /// Deletes the original file — ONLY possible with a verified quarantine
    /// reference. Re-hashes the file immediately before deleting and refuses on
    /// any mismatch, unsafe path, or reparse redirection.
    /// </summary>
    public async Task<FileRemediationResult> DeleteOriginalAsync(
        VerifiedQuarantineReference reference,
        IRemediationJournal journal,
        RemediationCorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (reference is null) throw new ArgumentNullException(nameof(reference));
        if (journal is null) throw new ArgumentNullException(nameof(journal));

        var path = reference.OriginalPath;

        var safe = _safePath.Evaluate(path);
        if (!safe.IsSafe)
            return Blocked(FileRemediationOutcome.BlockedUnsafePath, safe.Reason);

        if (!_fs.Exists(path))
            return Blocked(FileRemediationOutcome.BlockedSourceMissing, "Original file is no longer present; nothing to delete (quarantine copy retained).");

        if (_fs.IsReparsePoint(path))
            return Blocked(FileRemediationOutcome.BlockedReparsePath, "Original path is a reparse point/symlink.");

        // TOCTOU: re-hash the file as it is NOW and require it to match what was
        // quarantined. A swap between quarantine and delete is refused.
        FileHashValue observed = await _hash.ComputeAsync(path, cancellationToken).ConfigureAwait(false);
        if (!observed.Matches(reference.QuarantinedHash))
        {
            return new FileRemediationResult
            {
                Outcome = FileRemediationOutcome.BlockedHashMismatch,
                Reason = "Original file content changed after quarantine; refusing to delete a file that was not the quarantined content.",
                QuarantineId = reference.QuarantineId,
                ExpectedHash = reference.QuarantinedHash,
                ObservedHash = observed,
            };
        }

        AppendIntent(journal, correlationId, RemediationActionKind.DeleteFile, path, RollbackTokenKind.QuarantineRestore, observed.ToString());

        try
        {
            _fs.DeleteOriginal(path);
        }
        catch (Exception ex)
        {
            AppendOutcome(journal, correlationId, RemediationActionKind.DeleteFile, path, $"Failed: {ex.GetType().Name}");
            return new FileRemediationResult
            {
                Outcome = FileRemediationOutcome.Failed,
                Reason = $"Delete failed: {ex.GetType().Name}: {ex.Message}. Quarantine copy retained.",
                QuarantineId = reference.QuarantineId,
                RollbackToken = RollbackToken.For(RollbackTokenKind.QuarantineRestore, reference.QuarantineId, correlationId),
            };
        }

        AppendOutcome(journal, correlationId, RemediationActionKind.DeleteFile, path, "OriginalDeleted", RollbackTokenKind.QuarantineRestore);

        return new FileRemediationResult
        {
            Outcome = FileRemediationOutcome.OriginalDeleted,
            Reason = "Original deleted after verified quarantine and hash match.",
            QuarantineId = reference.QuarantineId,
            RollbackToken = RollbackToken.For(RollbackTokenKind.QuarantineRestore, reference.QuarantineId, correlationId),
            ObservedHash = observed,
        };
    }

    /// <summary>The typical flow: quarantine + verify, then delete the original.
    /// Delete runs ONLY if quarantine succeeded — quarantine-before-delete by
    /// control flow as well as by type.</summary>
    public async Task<FileRemediationResult> QuarantineAndDeleteAsync(
        FileRemediationRequest request,
        IRemediationJournal journal,
        RemediationCorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        var quarantine = await QuarantineAsync(request, journal, correlationId, cancellationToken).ConfigureAwait(false);
        if (quarantine.Outcome != FileRemediationOutcome.Quarantined || quarantine.QuarantineReference is null)
            return quarantine; // blocked — no delete attempted

        var delete = await DeleteOriginalAsync(quarantine.QuarantineReference, journal, correlationId, cancellationToken).ConfigureAwait(false);

        // Carry the quarantine reference forward so the caller can still roll back
        // even if the result is the delete outcome.
        return delete with { QuarantineReference = quarantine.QuarantineReference };
    }

    /// <summary>
    /// Restores a previously quarantined file through the UNCHANGED quarantine
    /// service (preserving its restore warnings and integrity checks). Requires a
    /// QuarantineRestore rollback token.
    /// </summary>
    public async Task<FileRemediationResult> RestoreAsync(
        RollbackToken token,
        string? destinationPath = null,
        bool allowOverwrite = false,
        CancellationToken cancellationToken = default)
    {
        if (token is null) throw new ArgumentNullException(nameof(token));
        if (token.Kind != RollbackTokenKind.QuarantineRestore || string.IsNullOrEmpty(token.Payload))
            return Blocked(FileRemediationOutcome.Failed, "Rollback token is not a quarantine-restore token.");

        var restore = await _quarantine.RestoreAsync(new QuarantineRestoreRequest
        {
            QuarantineId = token.Payload!,
            DestinationPath = destinationPath,
            AllowOverwrite = allowOverwrite,
        }, cancellationToken).ConfigureAwait(false);

        return restore.IsRestored
            ? new FileRemediationResult { Outcome = FileRemediationOutcome.Restored, Reason = restore.Message, QuarantineId = token.Payload }
            : new FileRemediationResult { Outcome = FileRemediationOutcome.Failed, Reason = $"Restore failed: {restore.Status} — {restore.Message}", QuarantineId = token.Payload };
    }

    /// <summary>
    /// Quarantine-store retention cleanup. Removes only the encrypted payload for
    /// the given quarantine id. By type it cannot reference an original path, so
    /// it can never delete an original file.
    /// </summary>
    public async Task<FileRemediationResult> DeleteQuarantineStoreRecordAsync(
        QuarantineStoreDeleteRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (string.IsNullOrWhiteSpace(request.QuarantineId))
            return Blocked(FileRemediationOutcome.StoreRecordNotFound, "Quarantine id is empty.");

        var record = await _quarantine.GetAsync(request.QuarantineId, cancellationToken).ConfigureAwait(false);
        if (record is null)
            return Blocked(FileRemediationOutcome.StoreRecordNotFound, "No quarantine record with that id.");

        bool removed = await _storeCleanup.RemovePayloadAsync(record.PayloadName, cancellationToken).ConfigureAwait(false);
        return new FileRemediationResult
        {
            Outcome = FileRemediationOutcome.StoreRecordDeleted,
            Reason = removed ? "Quarantine store payload removed (retention cleanup; original file not affected)." : "Quarantine payload already absent; nothing to remove.",
            QuarantineId = request.QuarantineId,
        };
    }

    /// <summary>
    /// Cleans a dropped temp payload. Restricted to temp roots and still routed
    /// through quarantine-before-delete (the payload is evidence): a temp file is
    /// quarantined, verified, then deleted.
    /// </summary>
    public async Task<FileRemediationResult> CleanTempPayloadAsync(
        TempPayloadCleanupRequest request,
        FileRemediationRequest fileRequest,
        IRemediationJournal journal,
        RemediationCorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));

        var safe = _safePath.Evaluate(request.Path);
        if (!safe.IsSafe)
            return Blocked(FileRemediationOutcome.BlockedUnsafePath, safe.Reason);

        if (!_safePath.IsWithinTempRoot(safe.NormalizedPath))
            return Blocked(FileRemediationOutcome.BlockedNotInTemp, "Temp cleanup target is not under a temp root.");

        var result = await QuarantineAndDeleteAsync(fileRequest with { OriginalPath = request.Path }, journal, correlationId, cancellationToken).ConfigureAwait(false);
        return result.Outcome == FileRemediationOutcome.OriginalDeleted
            ? result with { Outcome = FileRemediationOutcome.TempCleaned, Reason = "Temp payload quarantined and removed." }
            : result;
    }

    // ── Journal helpers (03A journal model) ─────────────────────────────────

    private void AppendIntent(IRemediationJournal journal, RemediationCorrelationId id, RemediationActionKind kind, string path, RollbackTokenKind rollbackKind, string? beforeRef)
        => journal.Append(new RemediationJournalRecord
        {
            CorrelationId = id,
            StepOrder = journal.ForCorrelation(id).Count,
            EntryKind = RemediationJournalEntryKind.Intent,
            ActionKind = kind,
            TargetMatchKey = $"File:{path.ToLowerInvariant()}",
            TimestampUtc = _clock.UtcNow,
            RollbackKind = rollbackKind,
            BeforeStateRef = beforeRef,
        });

    private void AppendOutcome(IRemediationJournal journal, RemediationCorrelationId id, RemediationActionKind kind, string path, string outcome, RollbackTokenKind rollbackKind = RollbackTokenKind.None)
        => journal.Append(new RemediationJournalRecord
        {
            CorrelationId = id,
            StepOrder = journal.ForCorrelation(id).Count,
            EntryKind = RemediationJournalEntryKind.Outcome,
            ActionKind = kind,
            TargetMatchKey = $"File:{path.ToLowerInvariant()}",
            TimestampUtc = _clock.UtcNow,
            RollbackKind = rollbackKind,
            Outcome = outcome,
        });

    private static FileRemediationResult Blocked(FileRemediationOutcome outcome, string reason)
        => new() { Outcome = outcome, Reason = reason };
}
