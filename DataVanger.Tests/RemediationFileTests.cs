using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Quarantine;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Files;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Rollback;
using DataVanger.Shared.Quarantine;
using Xunit;

// Phase 03B — file & quarantine remediation tests. Runnable via:
//   dotnet test --filter "FullyQualifiedName~Remediation".
// These prove the non-negotiable guarantees: quarantine-before-delete, hash
// verification, safe-path enforcement, store-delete distinction, and rollback
// through the unchanged quarantine service. The happy paths run against the REAL
// QuarantineService (in-memory store/crypto); failure paths inject fakes.
public class RemediationFileTests : IDisposable
{
    private readonly string _tempDir;

    public RemediationFileTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "dv-rem-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch (IOException) { /* best-effort temp cleanup */ }
        catch (UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }

    // ── Test infrastructure ─────────────────────────────────────────────────

    private string WriteTempFile(string content)
    {
        var path = Path.Combine(_tempDir, "evil-" + Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllText(path, content);
        return path;
    }

    private static (FileRemediationService svc, IQuarantineService quarantine, InMemoryQuarantineStore store)
        BuildWithRealQuarantine(ISafePathPolicy? safePath = null, IFileSystemRemediationOperations? fs = null)
    {
        var store = new InMemoryQuarantineStore();
        var service = new QuarantineService(
            store,
            new QuarantineCryptoProvider(),
            new InMemoryQuarantineKeyProtector("phase03b-seed"),
            new QuarantineOptions());

        var svc = new FileRemediationService(
            new QuarantineServiceRemediationGateway(service),
            new QuarantineStoreCleanup(store),
            new Sha256FileHashProvider(),
            safePath ?? new RemediationSafePathPolicy(),
            fs ?? new SystemFileRemediationOperations());

        return (svc, service, store);
    }

    private sealed class FakeFs : IFileSystemRemediationOperations
    {
        public bool ExistsResult { get; init; } = true;
        public bool ReparseResult { get; init; }
        public int DeleteCount { get; private set; }
        public bool Exists(string path) => ExistsResult;
        public bool IsReparsePoint(string path) => ReparseResult;
        public void DeleteOriginal(string path) => DeleteCount++;
    }

    /// <summary>Gateway that fails quarantine or verification on demand. The
    /// original temp file is real, so a blocked delete leaves it on disk.</summary>
    private sealed class FailingGateway : IQuarantineRemediationGateway
    {
        public QuarantineStatus QuarantineStatus { get; init; } = QuarantineStatus.Success;
        public bool VerifyIntact { get; init; } = true;

        public Task<QuarantineResult> QuarantineAsync(QuarantineRequest request, CancellationToken ct = default)
            => Task.FromResult(QuarantineStatus == QuarantineStatus.Success
                ? QuarantineResult.Stored(new QuarantineRecord { QuarantineId = "fake-id", OriginalPath = request.SourcePath, PayloadName = "fake.qbin", OriginalSha256 = "deadbeef" }, originalDeleteFailed: false, "stored")
                : QuarantineResult.Failure(QuarantineStatus, "quarantine refused"));

        public Task<QuarantineIntegrityResult> VerifyAsync(string id, CancellationToken ct = default)
            => Task.FromResult(new QuarantineIntegrityResult
            {
                Status = VerifyIntact ? QuarantineStatus.Success : QuarantineStatus.IntegrityCheckFailed,
                QuarantineId = id,
                MetadataIntact = VerifyIntact,
                PayloadIntact = VerifyIntact,
                Message = VerifyIntact ? "ok" : "tampered",
            });

        public Task<QuarantineRestoreResult> RestoreAsync(QuarantineRestoreRequest request, CancellationToken ct = default)
            => Task.FromResult(QuarantineRestoreResult.Failure(QuarantineStatus.RestoreFailed, "n/a"));

        public Task<QuarantineRecord?> GetAsync(string id, CancellationToken ct = default)
            => Task.FromResult<QuarantineRecord?>(new QuarantineRecord { QuarantineId = id, PayloadName = "fake.qbin", OriginalSha256 = "deadbeef" });
    }

    private sealed class NoopStoreCleanup : IQuarantineStoreCleanup
    {
        public Task<bool> RemovePayloadAsync(string payloadName, CancellationToken ct = default) => Task.FromResult(false);
    }

    private static FileRemediationService WithGateway(IQuarantineRemediationGateway gw, IFileSystemRemediationOperations fs, ISafePathPolicy? safePath = null)
        => new(gw, new NoopStoreCleanup(), new Sha256FileHashProvider(), safePath ?? new RemediationSafePathPolicy(), fs);

    private static FileRemediationRequest Req(string path) => new()
    {
        OriginalPath = path,
        Classification = QuarantineThreatClassification.ConfirmedMalware,
        Origin = QuarantineRequestOrigin.ManualUserApproved,
    };

    // ── Positive: quarantine produces a verified reference ──────────────────

    [Fact]
    public async Task Quarantine_ProducesVerifiedReference_WithoutDeletingOriginal()
    {
        var (svc, _, _) = BuildWithRealQuarantine();
        var path = WriteTempFile("malware-bytes");
        var journal = new InMemoryRemediationJournal();

        var result = await svc.QuarantineAsync(Req(path), journal, RemediationCorrelationId.New());

        Assert.Equal(FileRemediationOutcome.Quarantined, result.Outcome);
        Assert.NotNull(result.QuarantineReference);
        Assert.True(result.RollbackToken!.CanRollback);
        Assert.True(File.Exists(path), "Quarantine must not delete the original.");
    }

    // ── Positive: quarantine-then-delete removes the original AFTER quarantine ─

    [Fact]
    public async Task QuarantineAndDelete_RemovesOriginal_OnlyAfterQuarantine()
    {
        var (svc, quarantine, _) = BuildWithRealQuarantine();
        var path = WriteTempFile("malware-bytes-2");
        var journal = new InMemoryRemediationJournal();

        var result = await svc.QuarantineAndDeleteAsync(Req(path), journal, RemediationCorrelationId.New());

        Assert.Equal(FileRemediationOutcome.OriginalDeleted, result.Outcome);
        Assert.False(File.Exists(path), "Original must be deleted after verified quarantine.");

        // The quarantine record still exists and is independently verifiable.
        var list = await quarantine.ListAsync();
        Assert.Single(list);
        var integrity = await quarantine.VerifyAsync(result.QuarantineId!);
        Assert.True(integrity.IsIntact);
    }

    [Fact]
    public async Task QuarantineAndDelete_JournalsQuarantineIntentBeforeDelete()
    {
        var (svc, _, _) = BuildWithRealQuarantine();
        var path = WriteTempFile("ordered");
        var journal = new InMemoryRemediationJournal();
        var corr = RemediationCorrelationId.New();

        await svc.QuarantineAndDeleteAsync(Req(path), journal, corr);

        var records = journal.ForCorrelation(corr);
        var quarantineIntent = records.First(r => r.ActionKind == RemediationActionKind.QuarantineFile && r.EntryKind == RemediationJournalEntryKind.Intent);
        var deleteIntent = records.First(r => r.ActionKind == RemediationActionKind.DeleteFile && r.EntryKind == RemediationJournalEntryKind.Intent);
        Assert.True(records.ToList().IndexOf(quarantineIntent) < records.ToList().IndexOf(deleteIntent),
            "Quarantine intent must be journaled before delete intent.");
    }

    // ── Negative: quarantine failure blocks delete ──────────────────────────

    [Fact]
    public async Task Delete_Blocked_WhenQuarantineFails_OriginalUntouched()
    {
        var path = WriteTempFile("stays");
        var fs = new SystemFileRemediationOperations();
        var svc = WithGateway(new FailingGateway { QuarantineStatus = QuarantineStatus.EncryptionFailed }, fs);

        var result = await svc.QuarantineAndDeleteAsync(Req(path), new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(FileRemediationOutcome.BlockedQuarantineFailed, result.Outcome);
        Assert.True(File.Exists(path), "A failed quarantine must never delete the original.");
    }

    [Fact]
    public async Task Delete_Blocked_WhenQuarantineUnverified_OriginalUntouched()
    {
        var path = WriteTempFile("stays-2");
        var fs = new SystemFileRemediationOperations();
        var svc = WithGateway(new FailingGateway { QuarantineStatus = QuarantineStatus.Success, VerifyIntact = false }, fs);

        var result = await svc.QuarantineAndDeleteAsync(Req(path), new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(FileRemediationOutcome.BlockedQuarantineUnverified, result.Outcome);
        Assert.True(File.Exists(path), "An unverified quarantine must never delete the original.");
    }

    [Fact]
    public async Task Quarantine_Blocked_WhenRecordHashDiffersFromPreQuarantineHash()
    {
        var path = WriteTempFile("pre-quarantine-content");
        var fs = new SystemFileRemediationOperations();
        var svc = WithGateway(new FailingGateway { QuarantineStatus = QuarantineStatus.Success, VerifyIntact = true }, fs);

        var result = await svc.QuarantineAsync(Req(path), new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(FileRemediationOutcome.BlockedHashMismatch, result.Outcome);
        Assert.Null(result.QuarantineReference);
        Assert.True(File.Exists(path), "A hash mismatch must not delete the original.");
        Assert.NotEqual(result.ExpectedHash, result.ObservedHash);
    }

    // ── Negative: hash mismatch (TOCTOU) blocks delete ──────────────────────

    [Fact]
    public async Task Delete_Blocked_OnHashMismatch_AfterFileSwapped()
    {
        var (svc, _, _) = BuildWithRealQuarantine();
        var path = WriteTempFile("original-content");
        var journal = new InMemoryRemediationJournal();
        var corr = RemediationCorrelationId.New();

        var quarantine = await svc.QuarantineAsync(Req(path), journal, corr);
        Assert.Equal(FileRemediationOutcome.Quarantined, quarantine.Outcome);

        // Swap the file content AFTER quarantine (TOCTOU).
        File.WriteAllText(path, "swapped-content");

        var delete = await svc.DeleteOriginalAsync(quarantine.QuarantineReference!, journal, corr);

        Assert.Equal(FileRemediationOutcome.BlockedHashMismatch, delete.Outcome);
        Assert.True(File.Exists(path), "A swapped file must not be deleted.");
        Assert.NotEqual(delete.ExpectedHash, delete.ObservedHash);
    }

    // ── Negative: safe-path + reparse refusals ──────────────────────────────

    [Fact]
    public async Task Quarantine_Blocked_OnSystemPath()
    {
        // Force a system root into the denylist so the test is deterministic
        // cross-platform without needing a real system file.
        var policy = new RemediationSafePathPolicy(additionalForbiddenRoots: new[] { _tempDir });
        var (svc, _, _) = BuildWithRealQuarantine(safePath: policy);
        var path = Path.Combine(_tempDir, "evil.exe");
        File.WriteAllText(path, "x");

        var result = await svc.QuarantineAsync(Req(path), new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(FileRemediationOutcome.BlockedUnsafePath, result.Outcome);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task Quarantine_Blocked_OnReparsePath()
    {
        var fs = new FakeFs { ExistsResult = true, ReparseResult = true };
        var svc = WithGateway(new FailingGateway(), fs);
        var path = Path.Combine(_tempDir, "link.exe");

        var result = await svc.QuarantineAsync(Req(path), new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(FileRemediationOutcome.BlockedReparsePath, result.Outcome);
        Assert.Equal(0, fs.DeleteCount);
    }

    // ── Rollback restores through the (unchanged) quarantine service ────────

    [Fact]
    public async Task Rollback_RestoresThroughQuarantine()
    {
        var (svc, _, _) = BuildWithRealQuarantine();
        var path = WriteTempFile("restore-me");
        var journal = new InMemoryRemediationJournal();
        var corr = RemediationCorrelationId.New();

        var deleted = await svc.QuarantineAndDeleteAsync(Req(path), journal, corr);
        Assert.Equal(FileRemediationOutcome.OriginalDeleted, deleted.Outcome);
        Assert.False(File.Exists(path));

        var restore = await svc.RestoreAsync(deleted.RollbackToken!, destinationPath: path, allowOverwrite: false);

        Assert.Equal(FileRemediationOutcome.Restored, restore.Outcome);
        Assert.True(File.Exists(path), "Rollback must restore the original through quarantine.");
        Assert.Equal("restore-me", File.ReadAllText(path));
    }

    [Fact]
    public async Task Restore_Rejects_NonQuarantineToken()
    {
        var (svc, _, _) = BuildWithRealQuarantine();
        var bogus = RollbackToken.Irreversible(RemediationCorrelationId.New());

        var restore = await svc.RestoreAsync(bogus);

        Assert.Equal(FileRemediationOutcome.Failed, restore.Outcome);
    }

    // ── Quarantine-store delete is distinct and removes only the payload ────

    [Fact]
    public async Task StoreDelete_RemovesOnlyPayload_NotOriginal()
    {
        var (svc, _, store) = BuildWithRealQuarantine();
        var path = WriteTempFile("store-delete");
        var journal = new InMemoryRemediationJournal();

        var quarantine = await svc.QuarantineAsync(Req(path), journal, RemediationCorrelationId.New());
        var payloadName = quarantine.QuarantineReference!.PayloadName;
        Assert.True(await store.PayloadExistsAsync(payloadName));

        var storeDelete = await svc.DeleteQuarantineStoreRecordAsync(new QuarantineStoreDeleteRequest { QuarantineId = quarantine.QuarantineId! });

        Assert.Equal(FileRemediationOutcome.StoreRecordDeleted, storeDelete.Outcome);
        Assert.False(await store.PayloadExistsAsync(payloadName), "Store delete must remove the payload.");
        Assert.True(File.Exists(path), "Store delete must NOT touch the original file.");
    }

    [Fact]
    public async Task StoreDelete_UnknownId_ReturnsNotFound()
    {
        var (svc, _, _) = BuildWithRealQuarantine();
        var result = await svc.DeleteQuarantineStoreRecordAsync(new QuarantineStoreDeleteRequest { QuarantineId = "does-not-exist" });
        Assert.Equal(FileRemediationOutcome.StoreRecordNotFound, result.Outcome);
    }

    // ── Type-level guarantees (impossible-by-construction) ──────────────────

    [Fact]
    public void DeleteBeforeQuarantine_IsImpossible_NoPathOnlyDeleteOverload()
    {
        // The only DeleteOriginalAsync overload requires a VerifiedQuarantineReference.
        var deleteOverloads = typeof(FileRemediationService)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => m.Name == "DeleteOriginalAsync")
            .ToArray();

        Assert.Single(deleteOverloads);
        Assert.Equal(typeof(VerifiedQuarantineReference), deleteOverloads[0].GetParameters()[0].ParameterType);
    }

    [Fact]
    public void VerifiedQuarantineReference_HasNoPublicConstructor()
    {
        // Cannot be fabricated to bypass quarantine — only produced by QuarantineAsync.
        Assert.Empty(typeof(VerifiedQuarantineReference).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
    }

    [Fact]
    public void QuarantineStoreDeleteRequest_CannotReferenceAFilesystemPath()
    {
        var props = typeof(QuarantineStoreDeleteRequest)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .ToArray();

        Assert.Equal(new[] { "QuarantineId" }, props);
        Assert.DoesNotContain("Path", props);
        Assert.DoesNotContain("OriginalPath", props);
    }
}
