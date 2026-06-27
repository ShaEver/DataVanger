using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Engine.Quarantine;

/// <summary>
/// Secure Quarantine V2 orchestrator.
///
/// Responsibilities:
///   - validate requests and enforce that AUTOMATIC quarantine is honored only
///     for ConfirmedMalware (anti-FP guarantee);
///   - compute SHA-256 of the original before quarantine;
///   - authenticate-encrypt the payload and write it atomically;
///   - integrity-protect and write the versioned record atomically;
///   - verify the committed payload + metadata before reporting success;
///   - optionally (and only when policy + request both allow, never in
///     development mode) remove the original — a failed deletion is reported,
///     never fatal;
///   - restore safely after integrity verification and strict path validation;
///   - emit report-safe audit telemetry for every operation.
///
/// What it never does: classify, create a malware verdict, encrypt files
/// outside the store, lock files, kill processes, execute restored files, or
/// throw on normal operational failures.
/// </summary>
public sealed class QuarantineService : IQuarantineService, IQuarantineIndex
{
    private readonly IQuarantineStore _store;
    private readonly IQuarantineCryptoProvider _crypto;
    private readonly IQuarantineKeyProtector _keyProtector;
    private readonly QuarantineOptions _options;
    private readonly IQuarantineAuditSink _audit;
    private readonly string _quarantineStoreRoot;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Action<string> _originalRemover;

    public QuarantineService(
        IQuarantineStore store,
        IQuarantineCryptoProvider crypto,
        IQuarantineKeyProtector keyProtector,
        QuarantineOptions options,
        string? quarantineStoreRoot = null,
        IQuarantineAuditSink? auditSink = null,
        Func<DateTimeOffset>? clock = null,
        Action<string>? originalRemover = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _crypto = crypto ?? throw new ArgumentNullException(nameof(crypto));
        _keyProtector = keyProtector ?? throw new ArgumentNullException(nameof(keyProtector));
        _options = (options ?? throw new ArgumentNullException(nameof(options))).Clone();
        _quarantineStoreRoot = quarantineStoreRoot ?? string.Empty;
        _audit = auditSink ?? NullQuarantineAuditSink.Instance;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        // Test seam: defaults to a real delete. Production callers never set this.
        _originalRemover = originalRemover ?? (path => File.Delete(path));
    }

    // ── Quarantine (store) ────────────────────────────────────────────────────
    public async Task<QuarantineResult> QuarantineAsync(QuarantineRequest request, CancellationToken cancellationToken = default)
    {
        if (request is null) return QuarantineResult.Failure(QuarantineStatus.SourceMissing, "Request was null.");

        Emit(QuarantineAuditEventKind.QuarantineRequested, null, null, request.Classification,
            QuarantineStatus.Unknown, null, "Quarantine requested.");

        if (cancellationToken.IsCancellationRequested)
            return Fail(QuarantineStatus.Cancelled, "Operation cancelled.", request.Classification);

        // Graceful degradation: unsupported key protection never crashes.
        if (!_keyProtector.IsSupported)
            return Fail(QuarantineStatus.UnsupportedPlatform,
                "Quarantine key protection is unavailable on this platform.", request.Classification);

        // Anti-FP: automatic quarantine is allowed ONLY for ConfirmedMalware.
        if (request.Origin == QuarantineRequestOrigin.Automatic &&
            request.Classification != QuarantineThreatClassification.ConfirmedMalware)
        {
            return Fail(QuarantineStatus.PolicyDenied,
                "Automatic quarantine is permitted only for ConfirmedMalware.", request.Classification);
        }

        if (string.IsNullOrWhiteSpace(request.SourcePath) || !File.Exists(request.SourcePath))
            return Fail(QuarantineStatus.SourceMissing, "Source file does not exist.", request.Classification);

        long size;
        string sha256;
        byte[] plaintext;
        try
        {
            var info = new FileInfo(request.SourcePath);
            size = info.Length;
            if (_options.MaxPayloadBytes > 0 && size > _options.MaxPayloadBytes)
                return Fail(QuarantineStatus.SourceTooLarge, "Source exceeds the configured maximum payload size.", request.Classification);

            using (var hashStream = new FileStream(request.SourcePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                sha256 = _crypto.ComputeSha256Hex(hashStream);
            }
            plaintext = await File.ReadAllBytesAsync(request.SourcePath, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return Fail(QuarantineStatus.Cancelled, "Operation cancelled.", request.Classification);
        }
        catch (UnauthorizedAccessException)
        {
            return Fail(QuarantineStatus.SourceAccessDenied, "Source file access denied.", request.Classification);
        }
        catch (Exception)
        {
            return Fail(QuarantineStatus.SourceReadFailed, "Source file could not be read/hashed.", request.Classification);
        }

        var keys = _keyProtector.GetKeyMaterial();

        // Non-predictable id, independent of path/hash.
        string id = Guid.NewGuid().ToString("N");
        string payloadName = id + ".qbin";

        QuarantineEncryptedPayload encrypted;
        try
        {
            encrypted = _crypto.EncryptPayload(plaintext, keys.PayloadKey);
        }
        catch (Exception)
        {
            return Fail(QuarantineStatus.EncryptionFailed, "Payload encryption failed.", request.Classification, id);
        }
        finally
        {
            Array.Clear(plaintext, 0, plaintext.Length);
        }

        var record = new QuarantineRecord
        {
            QuarantineId = id,
            SchemaVersion = QuarantineRecord.CurrentSchemaVersion,
            OriginalPath = request.SourcePath,
            OriginalFileName = Path.GetFileName(request.SourcePath),
            OriginalExtension = Path.GetExtension(request.SourcePath),
            OriginalSize = size,
            OriginalSha256 = sha256,
            PayloadName = payloadName,
            CreatedUtc = _clock(),
            DetectionSummary = request.DetectionSummary,
            ThreatClassification = request.Classification,
            EvidenceIds = new List<string>(request.EvidenceIds),
            SourceModule = request.SourceModule,
            RequestedAction = request.RequestedAction,
            ActionReason = request.ActionReason,
            RecordState = QuarantineRecordState.Created,
            PayloadEncryptionAlgorithm = _crypto.PayloadEncryptionAlgorithm,
            PayloadAuthenticationAlgorithm = _crypto.PayloadAuthenticationAlgorithm,
            MetadataIntegrityAlgorithm = _crypto.MetadataIntegrityAlgorithm,
            KeyProtectionMode = _keyProtector.Mode,
        };

        try
        {
            await _store.WritePayloadAsync(payloadName, encrypted, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return Fail(QuarantineStatus.Cancelled, "Operation cancelled.", request.Classification, id);
        }
        catch (Exception)
        {
            return Fail(QuarantineStatus.PayloadWriteFailed, "Encrypted payload could not be written.", request.Classification, id);
        }

        record.RecordState = QuarantineRecordState.Stored;
        try
        {
            await WriteRecordAsync(record, keys.MetadataKey, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            await SafeDeletePayloadAsync(payloadName).ConfigureAwait(false);
            return Fail(QuarantineStatus.Cancelled, "Operation cancelled.", request.Classification, id);
        }
        catch (Exception)
        {
            await SafeDeletePayloadAsync(payloadName).ConfigureAwait(false);
            return Fail(QuarantineStatus.MetadataWriteFailed, "Quarantine record could not be written.", request.Classification, id);
        }

        // Verify the committed artifacts before claiming success.
        var integrity = await VerifyAsync(id, cancellationToken).ConfigureAwait(false);
        if (!integrity.IsIntact)
        {
            await SafeDeletePayloadAsync(payloadName).ConfigureAwait(false);
            return Fail(QuarantineStatus.CommitFailed,
                "Post-commit integrity verification failed: " + integrity.Message, request.Classification, id);
        }

        record.LastVerifiedUtc = _clock();
        record.RecordState = QuarantineRecordState.Verified;

        // Original handling — only when explicitly requested AND policy allows AND not development mode.
        bool originalDeleteFailed = false;
        bool mayDelete = request.DeleteOriginalAfterStore && _options.AllowOriginalDeletion && !_options.DevelopmentMode;
        if (mayDelete)
        {
            try
            {
                _originalRemover(request.SourcePath);
                record.OriginalRemoved = !File.Exists(request.SourcePath);
                if (!record.OriginalRemoved) originalDeleteFailed = true;
            }
            catch (Exception)
            {
                originalDeleteFailed = true;
                record.OriginalRemoved = false;
            }
        }

        // Persist the verified state (re-signed).
        try
        {
            await WriteRecordAsync(record, keys.MetadataKey, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Payload is safely stored and verified; a failure to persist the
            // verified-state update is non-fatal. Keep the Stored record.
        }

        Emit(QuarantineAuditEventKind.QuarantineStored, id, sha256, request.Classification,
            QuarantineStatus.Success, record.RecordState,
            originalDeleteFailed ? "Stored; original retained (delete failed)." : "Stored and verified.");
        Emit(QuarantineAuditEventKind.QuarantineVerified, id, sha256, request.Classification,
            QuarantineStatus.Success, record.RecordState, "Quarantine payload + metadata verified.");

        if (originalDeleteFailed)
        {
            return new QuarantineResult
            {
                Status = QuarantineStatus.Success,
                QuarantineId = id,
                Record = record,
                OriginalDeleteFailed = true,
                Message = "Quarantine stored and verified; original file could not be removed.",
            };
        }

        return QuarantineResult.Stored(record, originalDeleteFailed: false,
            mayDelete ? "Quarantine stored, verified, original removed." : "Quarantine stored and verified; original retained.");
    }

    // ── Verify ────────────────────────────────────────────────────────────────
    public async Task<QuarantineIntegrityResult> VerifyAsync(string quarantineId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(quarantineId))
            return Integrity(QuarantineStatus.RecordNotFound, quarantineId ?? "", false, false, QuarantineRecordState.Corrupt, "Empty id.");

        if (!_keyProtector.IsSupported)
            return Integrity(QuarantineStatus.UnsupportedPlatform, quarantineId, false, false, QuarantineRecordState.Corrupt,
                "Key protection unavailable on this platform.");

        var stored = await ReadStoredAsync(quarantineId, cancellationToken).ConfigureAwait(false);
        if (stored is null)
            return Integrity(QuarantineStatus.RecordNotFound, quarantineId, false, false, QuarantineRecordState.Corrupt, "Record not found.");

        var keys = _keyProtector.GetKeyMaterial();

        // 1. Metadata integrity (HMAC) BEFORE trusting record contents.
        bool metadataIntact = _crypto.VerifyMetadataTag(stored.CanonicalMetadata, keys.MetadataKey, stored.MetadataTag);
        if (!metadataIntact)
        {
            Emit(QuarantineAuditEventKind.QuarantineMetadataTamperDetected, quarantineId, null,
                QuarantineThreatClassification.Clean, QuarantineStatus.MetadataTampered, QuarantineRecordState.Corrupt,
                "Quarantine metadata authentication failed (tamper detected).");
            return Integrity(QuarantineStatus.MetadataTampered, quarantineId, false, false, QuarantineRecordState.Corrupt,
                "Metadata authentication failed.");
        }

        QuarantineRecord record;
        try
        {
            record = QuarantineRecordSerializer.DeserializeRecord(stored.CanonicalMetadata);
        }
        catch (System.Exception)
        {
            return Integrity(QuarantineStatus.MetadataTampered, quarantineId, false, false, QuarantineRecordState.Corrupt,
                "Record could not be deserialized.");
        }

        // 2. Payload presence vs. corruption.
        bool payloadPresent = await _store.PayloadExistsAsync(record.PayloadName, cancellationToken).ConfigureAwait(false);
        if (!payloadPresent)
        {
            Emit(QuarantineAuditEventKind.QuarantinePayloadMissing, quarantineId, record.OriginalSha256,
                record.ThreatClassification, QuarantineStatus.PayloadMissing, QuarantineRecordState.MissingPayload,
                "Quarantine payload is missing.");
            return Integrity(QuarantineStatus.PayloadMissing, quarantineId, true, false, QuarantineRecordState.MissingPayload,
                "Payload missing.");
        }

        var payload = await _store.ReadPayloadAsync(record.PayloadName, cancellationToken).ConfigureAwait(false);
        if (payload is null)
        {
            // File exists but cannot be decoded => corrupt, not missing.
            Emit(QuarantineAuditEventKind.QuarantineIntegrityFailed, quarantineId, record.OriginalSha256,
                record.ThreatClassification, QuarantineStatus.IntegrityCheckFailed, QuarantineRecordState.Corrupt,
                "Quarantine payload is structurally corrupt.");
            return Integrity(QuarantineStatus.IntegrityCheckFailed, quarantineId, true, false, QuarantineRecordState.Corrupt,
                "Payload corrupt (undecodable).");
        }

        // 3. Payload authenticity + content hash match.
        byte[] plaintext;
        try
        {
            plaintext = _crypto.DecryptPayload(payload, keys.PayloadKey);
        }
        catch (QuarantineCryptoException)
        {
            Emit(QuarantineAuditEventKind.QuarantineIntegrityFailed, quarantineId, record.OriginalSha256,
                record.ThreatClassification, QuarantineStatus.IntegrityCheckFailed, QuarantineRecordState.Corrupt,
                "Quarantine payload authentication failed (tamper/corruption).");
            return Integrity(QuarantineStatus.IntegrityCheckFailed, quarantineId, true, false, QuarantineRecordState.Corrupt,
                "Payload authentication failed.");
        }

        string actualHash = _crypto.ComputeSha256Hex(plaintext);
        Array.Clear(plaintext, 0, plaintext.Length);

        bool payloadIntact = string.Equals(actualHash, record.OriginalSha256, StringComparison.OrdinalIgnoreCase);
        if (!payloadIntact)
        {
            Emit(QuarantineAuditEventKind.QuarantineIntegrityFailed, quarantineId, record.OriginalSha256,
                record.ThreatClassification, QuarantineStatus.IntegrityCheckFailed, QuarantineRecordState.Corrupt,
                "Decrypted payload hash does not match the recorded original hash.");
            return Integrity(QuarantineStatus.IntegrityCheckFailed, quarantineId, true, false, QuarantineRecordState.Corrupt,
                "Payload hash mismatch.");
        }

        return Integrity(QuarantineStatus.Success, quarantineId, true, true, QuarantineRecordState.Verified, "Intact.");
    }

    // ── Restore ───────────────────────────────────────────────────────────────
    public async Task<QuarantineRestoreResult> RestoreAsync(QuarantineRestoreRequest request, CancellationToken cancellationToken = default)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.QuarantineId))
            return QuarantineRestoreResult.Failure(QuarantineStatus.RecordNotFound, "Empty restore request.");

        Emit(QuarantineAuditEventKind.QuarantineRestoreRequested, request.QuarantineId, null,
            QuarantineThreatClassification.Clean, QuarantineStatus.Unknown, null, "Restore requested.");

        if (cancellationToken.IsCancellationRequested)
            return RestoreFail(QuarantineStatus.Cancelled, "Operation cancelled.", request.QuarantineId);

        if (!_keyProtector.IsSupported)
            return RestoreFail(QuarantineStatus.UnsupportedPlatform, "Key protection unavailable on this platform.", request.QuarantineId);

        var stored = await ReadStoredAsync(request.QuarantineId, cancellationToken).ConfigureAwait(false);
        if (stored is null)
            return RestoreFail(QuarantineStatus.RecordNotFound, "Record not found.", request.QuarantineId);

        var keys = _keyProtector.GetKeyMaterial();

        if (!_crypto.VerifyMetadataTag(stored.CanonicalMetadata, keys.MetadataKey, stored.MetadataTag))
        {
            Emit(QuarantineAuditEventKind.QuarantineMetadataTamperDetected, request.QuarantineId, null,
                QuarantineThreatClassification.Clean, QuarantineStatus.MetadataTampered, QuarantineRecordState.Corrupt,
                "Restore refused: metadata authentication failed.");
            return RestoreFail(QuarantineStatus.MetadataTampered, "Metadata authentication failed.", request.QuarantineId);
        }

        QuarantineRecord record;
        try { record = QuarantineRecordSerializer.DeserializeRecord(stored.CanonicalMetadata); }
        catch (System.Exception) { return RestoreFail(QuarantineStatus.MetadataTampered, "Record could not be deserialized.", request.QuarantineId); }

        bool payloadPresent = await _store.PayloadExistsAsync(record.PayloadName, cancellationToken).ConfigureAwait(false);
        if (!payloadPresent)
        {
            Emit(QuarantineAuditEventKind.QuarantinePayloadMissing, request.QuarantineId, record.OriginalSha256,
                record.ThreatClassification, QuarantineStatus.PayloadMissing, QuarantineRecordState.MissingPayload,
                "Restore refused: payload missing.");
            await UpdateStateAsync(record, keys.MetadataKey, QuarantineRecordState.MissingPayload, cancellationToken).ConfigureAwait(false);
            return RestoreFail(QuarantineStatus.PayloadMissing, "Payload missing.", request.QuarantineId, record);
        }

        var payload = await _store.ReadPayloadAsync(record.PayloadName, cancellationToken).ConfigureAwait(false);
        if (payload is null)
        {
            Emit(QuarantineAuditEventKind.QuarantineIntegrityFailed, request.QuarantineId, record.OriginalSha256,
                record.ThreatClassification, QuarantineStatus.IntegrityCheckFailed, QuarantineRecordState.Corrupt,
                "Restore refused: payload corrupt.");
            await UpdateStateAsync(record, keys.MetadataKey, QuarantineRecordState.Corrupt, cancellationToken).ConfigureAwait(false);
            return RestoreFail(QuarantineStatus.IntegrityCheckFailed, "Payload corrupt (undecodable).", request.QuarantineId, record);
        }

        byte[] plaintext;
        try
        {
            plaintext = _crypto.DecryptPayload(payload, keys.PayloadKey);
        }
        catch (QuarantineCryptoException)
        {
            Emit(QuarantineAuditEventKind.QuarantineIntegrityFailed, request.QuarantineId, record.OriginalSha256,
                record.ThreatClassification, QuarantineStatus.IntegrityCheckFailed, QuarantineRecordState.Corrupt,
                "Restore refused: payload authentication failed.");
            await UpdateStateAsync(record, keys.MetadataKey, QuarantineRecordState.Corrupt, cancellationToken).ConfigureAwait(false);
            return RestoreFail(QuarantineStatus.IntegrityCheckFailed, "Payload authentication failed.", request.QuarantineId, record);
        }

        // Confirm the decrypted content matches the recorded original hash.
        if (!string.Equals(_crypto.ComputeSha256Hex(plaintext), record.OriginalSha256, StringComparison.OrdinalIgnoreCase))
        {
            Array.Clear(plaintext, 0, plaintext.Length);
            Emit(QuarantineAuditEventKind.QuarantineIntegrityFailed, request.QuarantineId, record.OriginalSha256,
                record.ThreatClassification, QuarantineStatus.IntegrityCheckFailed, QuarantineRecordState.Corrupt,
                "Restore refused: payload hash mismatch.");
            await UpdateStateAsync(record, keys.MetadataKey, QuarantineRecordState.Corrupt, cancellationToken).ConfigureAwait(false);
            return RestoreFail(QuarantineStatus.IntegrityCheckFailed, "Payload hash mismatch.", request.QuarantineId, record);
        }

        // Validate destination path AFTER integrity passes.
        string candidate = string.IsNullOrWhiteSpace(request.DestinationPath) ? record.OriginalPath : request.DestinationPath!;
        var pathOutcome = QuarantinePathPolicy.ValidateRestoreDestination(candidate, _quarantineStoreRoot, _options);
        if (!pathOutcome.IsValid)
        {
            Array.Clear(plaintext, 0, plaintext.Length);
            Emit(QuarantineAuditEventKind.QuarantineRestoreFailed, request.QuarantineId, record.OriginalSha256,
                record.ThreatClassification, QuarantineStatus.RestorePathInvalid, record.RecordState,
                "Restore refused: invalid destination path.");
            return RestoreFail(QuarantineStatus.RestorePathInvalid, "Invalid restore path: " + pathOutcome.Reason, request.QuarantineId, record);
        }

        string destination = pathOutcome.NormalizedPath;
        if (File.Exists(destination) && !request.AllowOverwrite)
        {
            Array.Clear(plaintext, 0, plaintext.Length);
            Emit(QuarantineAuditEventKind.QuarantineRestoreFailed, request.QuarantineId, record.OriginalSha256,
                record.ThreatClassification, QuarantineStatus.RestoreTargetExists, record.RecordState,
                "Restore refused: target exists and overwrite not allowed.");
            return RestoreFail(QuarantineStatus.RestoreTargetExists, "Target exists; overwrite not allowed.", request.QuarantineId, record);
        }

        // Write decrypted bytes to a temp file, then atomically move into place.
        string tempPath = destination + ".dvrestore-" + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var destDir = Path.GetDirectoryName(destination);
            if (!string.IsNullOrEmpty(destDir)) Directory.CreateDirectory(destDir);

            await File.WriteAllBytesAsync(tempPath, plaintext, cancellationToken).ConfigureAwait(false);
            // NOTE: restored files are NEVER executed by the quarantine service.
            File.Move(tempPath, destination, overwrite: request.AllowOverwrite);
        }
        catch (OperationCanceledException)
        {
            TryDeleteTemp(tempPath);
            Array.Clear(plaintext, 0, plaintext.Length);
            return RestoreFail(QuarantineStatus.Cancelled, "Operation cancelled.", request.QuarantineId, record);
        }
        catch (Exception ex)
        {
            TryDeleteTemp(tempPath);
            Array.Clear(plaintext, 0, plaintext.Length);
            Emit(QuarantineAuditEventKind.QuarantineRestoreFailed, request.QuarantineId, record.OriginalSha256,
                record.ThreatClassification, QuarantineStatus.RestoreFailed, record.RecordState,
                "Restore failed while writing the destination.");
            await UpdateStateAsync(record, keys.MetadataKey, QuarantineRecordState.RestoreFailed, cancellationToken).ConfigureAwait(false);
            return RestoreFail(QuarantineStatus.RestoreFailed, "Restore write failed: " + ex.GetType().Name, request.QuarantineId, record);
        }
        finally
        {
            Array.Clear(plaintext, 0, plaintext.Length);
        }

        record.RestoreCount += 1;
        record.RecordState = QuarantineRecordState.Restored;
        await UpdateStateAsync(record, keys.MetadataKey, QuarantineRecordState.Restored, cancellationToken).ConfigureAwait(false);

        Emit(QuarantineAuditEventKind.QuarantineRestored, request.QuarantineId, record.OriginalSha256,
            record.ThreatClassification, QuarantineStatus.Success, QuarantineRecordState.Restored,
            "Quarantine restored after integrity verification.");

        return QuarantineRestoreResult.Restored(record, destination, "Restored after integrity verification.");
    }

    // ── List / Get ─────────────────────────────────────────────────────────────
    public async Task<IReadOnlyList<QuarantineIndexEntry>> ListAsync(CancellationToken cancellationToken = default)
    {
        var ids = await _store.ListRecordIdsAsync(cancellationToken).ConfigureAwait(false);
        var entries = new List<QuarantineIndexEntry>(ids.Count);
        var keys = _keyProtector.IsSupported ? _keyProtector.GetKeyMaterial() : null;

        foreach (var id in ids)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var stored = await ReadStoredAsync(id, cancellationToken).ConfigureAwait(false);
            if (stored is null) continue;

            // The index is a convenience view; mark entries whose metadata fails
            // authentication as Corrupt rather than trusting their contents.
            bool intact = keys is not null && _crypto.VerifyMetadataTag(stored.CanonicalMetadata, keys.MetadataKey, stored.MetadataTag);
            QuarantineRecord? record = null;
            if (intact)
            {
                try { record = QuarantineRecordSerializer.DeserializeRecord(stored.CanonicalMetadata); }
                catch (System.Exception) { record = null; }
            }

            if (record is null)
            {
                entries.Add(new QuarantineIndexEntry { QuarantineId = id, RecordState = QuarantineRecordState.Corrupt });
                continue;
            }

            entries.Add(new QuarantineIndexEntry
            {
                QuarantineId = record.QuarantineId,
                OriginalFileName = record.OriginalFileName,
                OriginalSha256 = record.OriginalSha256,
                CreatedUtc = record.CreatedUtc,
                RecordState = record.RecordState,
                ThreatClassification = record.ThreatClassification,
            });
        }

        return entries;
    }

    public async Task<QuarantineRecord?> GetAsync(string quarantineId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(quarantineId) || !_keyProtector.IsSupported) return null;
        var stored = await ReadStoredAsync(quarantineId, cancellationToken).ConfigureAwait(false);
        if (stored is null) return null;

        var keys = _keyProtector.GetKeyMaterial();
        if (!_crypto.VerifyMetadataTag(stored.CanonicalMetadata, keys.MetadataKey, stored.MetadataTag))
            return null; // do not return unauthenticated metadata

        try { return QuarantineRecordSerializer.DeserializeRecord(stored.CanonicalMetadata); }
        catch (System.Exception) { return null; }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────
    private Task WriteRecordAsync(QuarantineRecord record, byte[] metadataKey, CancellationToken ct)
    {
        var canonical = QuarantineRecordSerializer.SerializeRecord(record);
        var tag = _crypto.ComputeMetadataTag(canonical, metadataKey);
        return _store.WriteRecordAsync(record, canonical, tag, ct);
    }

    private async Task UpdateStateAsync(QuarantineRecord record, byte[] metadataKey, QuarantineRecordState state, CancellationToken ct)
    {
        record.RecordState = state;
        try { await WriteRecordAsync(record, metadataKey, ct).ConfigureAwait(false); }
        catch (System.Exception) { /* state-update persistence is best-effort and never fatal */ }
    }

    private async Task<QuarantineStoredRecord?> ReadStoredAsync(string id, CancellationToken ct)
    {
        try { return await _store.ReadRecordAsync(id, ct).ConfigureAwait(false); }
        catch (System.Exception) { return null; }
    }

    private async Task SafeDeletePayloadAsync(string payloadName)
    {
        try { await _store.DeletePayloadAsync(payloadName, CancellationToken.None).ConfigureAwait(false); }
        catch (System.Exception) { /* cleanup is best-effort */ }
    }

    private static void TryDeleteTemp(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch (System.Exception) { /* best-effort */ }
    }

    private QuarantineResult Fail(QuarantineStatus status, string message, QuarantineThreatClassification cls, string? id = null)
    {
        Emit(QuarantineAuditEventKind.QuarantineFailed, id, null, cls, status, null, message);
        return QuarantineResult.Failure(status, message, id);
    }

    private QuarantineRestoreResult RestoreFail(QuarantineStatus status, string message, string id, QuarantineRecord? record = null)
    {
        Emit(QuarantineAuditEventKind.QuarantineRestoreFailed, id, record?.OriginalSha256,
            record?.ThreatClassification ?? QuarantineThreatClassification.Clean, status, record?.RecordState, message);
        return QuarantineRestoreResult.Failure(status, message, id, record);
    }

    private static QuarantineIntegrityResult Integrity(QuarantineStatus status, string id, bool metadataIntact, bool payloadIntact,
        QuarantineRecordState state, string message)
        => new()
        {
            Status = status,
            QuarantineId = id,
            MetadataIntact = metadataIntact,
            PayloadIntact = payloadIntact,
            RecordState = state,
            Message = message,
        };

    private void Emit(QuarantineAuditEventKind kind, string? id, string? sha256, QuarantineThreatClassification cls,
        QuarantineStatus status, QuarantineRecordState? state, string message)
    {
        try
        {
            _audit.Publish(new QuarantineAuditEvent
            {
                Kind = kind,
                TimestampUtc = _clock(),
                QuarantineId = id,
                OriginalSha256 = sha256,
                Classification = cls,
                ResultStatus = status,
                RecordState = state,
                Message = message,
            });
        }
        catch (System.Exception)
        {
            // Audit telemetry must never break a quarantine operation.
        }
    }
}
