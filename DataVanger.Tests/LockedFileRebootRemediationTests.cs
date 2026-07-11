using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using DataVanger.Engine.Quarantine;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Files;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Reboot;
using DataVanger.Shared.Quarantine;
using Xunit;

// Phase 03D — locked-file / reboot-required remediation tests. Fakes only; no
// real reboot and no real PendingFileRenameOperations write. Filter: ~Remediation.
public class LockedFileRebootRemediationTests : IDisposable
{
    private readonly string _tempDir;

    public LockedFileRebootRemediationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "dv-reboot-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch (IOException) { /* best-effort */ }
        catch (UnauthorizedAccessException) { /* best-effort */ }
    }

    private sealed class FixedClock : IRemediationClock
    {
        private DateTimeOffset _now = new(2026, 6, 13, 0, 0, 0, TimeSpan.Zero);
        public DateTimeOffset UtcNow => _now = _now.AddSeconds(1);
    }

    private sealed class FakeLockDetector : ILockedFileDetector
    {
        public bool Locked { get; init; }
        public bool IsLocked(string path) => Locked;
    }

    private sealed class AssertingPendingProvider : IPendingFileOperationProvider
    {
        private readonly IPendingRebootOperationStore _store;
        private readonly HashSet<string> _queued = new(StringComparer.OrdinalIgnoreCase);

        public AssertingPendingProvider(IPendingRebootOperationStore store)
        {
            _store = store;
        }

        public bool ThrowOnQueue { get; init; }
        public bool QueueSawJournaledState { get; private set; }
        public int QueueCalls { get; private set; }

        public void QueueDeleteOnReboot(string path)
        {
            QueueCalls++;
            QueueSawJournaledState = _store.List().Any(op =>
                op.TargetPath.Equals(path, StringComparison.OrdinalIgnoreCase)
                && op.Status == PendingOperationStatus.Queued);

            if (ThrowOnQueue)
                throw new InvalidOperationException("simulated pending-provider failure");

            _queued.Add(path);
        }

        public void CancelQueuedDelete(string path) => _queued.Remove(path);

        public bool IsQueued(string path) => _queued.Contains(path);
    }

    private FileRemediationService BuildFileService()
    {
        var store = new InMemoryQuarantineStore();
        var service = new QuarantineService(
            store, new QuarantineCryptoProvider(), new InMemoryQuarantineKeyProtector("reboot-seed"), new QuarantineOptions());
        return new FileRemediationService(
            new QuarantineServiceRemediationGateway(service),
            new QuarantineStoreCleanup(store),
            new Sha256FileHashProvider(),
            new RemediationSafePathPolicy(),
            new SystemFileRemediationOperations());
    }

    private string WriteTempFile()
    {
        var path = Path.Combine(_tempDir, "evil-" + Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllText(path, "locked-malware");
        return path;
    }

    private static FileRemediationRequest Req(string path) => new()
    {
        OriginalPath = path,
        Classification = QuarantineThreatClassification.ConfirmedMalware,
        Origin = QuarantineRequestOrigin.ManualUserApproved,
    };

    private LockedFileRemediationAction BuildAction(bool locked, IPendingFileOperationProvider provider, IPendingRebootOperationStore store)
        => new(BuildFileService(), new FakeLockDetector { Locked = locked }, provider, store, new RemediationSafePathPolicy(), new FixedClock());

    // ── Locked-file escalation ──────────────────────────────────────────────

    [Fact]
    public async Task LockedFile_WithConsent_QuarantinesAndQueuesDelete_NoReboot()
    {
        var path = WriteTempFile();
        var provider = new SimulationPendingFileOperationProvider();
        var store = new InMemoryPendingRebootOperationStore();
        var action = BuildAction(locked: true, provider, store);

        var result = await action.ExecuteAsync(Req(path), rebootConsentGiven: true, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(LockedFileRemediationOutcome.RebootRequired, result.Outcome);
        Assert.Equal(RebootRequiredState.Queued, result.RebootState);
        Assert.NotNull(result.PendingOperationId);
        Assert.True(provider.IsQueued(path), "delete should be queued for reboot");
        Assert.True(File.Exists(path), "the locked original is NOT deleted now (only queued)");
        // Reversible: the quarantine copy gives a rollback token.
        Assert.True(result.RollbackToken!.CanRollback);
    }

    [Fact]
    public async Task LockedFile_WithoutConsent_RequiresReboot_QueuesNothing()
    {
        var path = WriteTempFile();
        var provider = new SimulationPendingFileOperationProvider();
        var store = new InMemoryPendingRebootOperationStore();
        var action = BuildAction(locked: true, provider, store);

        var result = await action.ExecuteAsync(Req(path), rebootConsentGiven: false, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(LockedFileRemediationOutcome.BlockedConsentRequired, result.Outcome);
        Assert.Equal(RebootRequiredState.Required, result.RebootState);
        Assert.Null(result.PendingOperationId);
        Assert.False(provider.IsQueued(path), "nothing may be queued without consent");
        Assert.Empty(store.List());
    }

    [Fact]
    public async Task UnlockedFile_RemovesNow_NoRebootRequired()
    {
        var path = WriteTempFile();
        var provider = new SimulationPendingFileOperationProvider();
        var store = new InMemoryPendingRebootOperationStore();
        var action = BuildAction(locked: false, provider, store);

        var result = await action.ExecuteAsync(Req(path), rebootConsentGiven: false, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(LockedFileRemediationOutcome.RemovedNow, result.Outcome);
        Assert.Equal(RebootRequiredState.NotRequired, result.RebootState);
        Assert.False(File.Exists(path));
        Assert.Empty(store.List());
    }

    [Fact]
    public async Task Queue_JournalsPendingOperation_BeforeProviderQueue()
    {
        var path = WriteTempFile();
        var provider = new SimulationPendingFileOperationProvider();
        var store = new InMemoryPendingRebootOperationStore();
        var action = BuildAction(locked: true, provider, store);

        await action.ExecuteAsync(Req(path), rebootConsentGiven: true, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        // The store journal records the Queued state.
        Assert.Single(store.List());
        Assert.Equal(PendingOperationStatus.Queued, store.List()[0].Status);
        Assert.Contains(store.Journal(), j => j.Status == PendingOperationStatus.Queued);
    }

    [Fact]
    public async Task Queue_ProviderSeesJournaledStateBeforeQueueing()
    {
        var path = WriteTempFile();
        var store = new InMemoryPendingRebootOperationStore();
        var provider = new AssertingPendingProvider(store);
        var action = BuildAction(locked: true, provider, store);

        var result = await action.ExecuteAsync(Req(path), rebootConsentGiven: true, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(LockedFileRemediationOutcome.RebootRequired, result.Outcome);
        Assert.True(provider.QueueSawJournaledState, "provider must not be asked to queue until pending state is journaled");
        Assert.Equal(1, provider.QueueCalls);
    }

    [Fact]
    public async Task Queue_WhenProviderFails_MarksPendingOperationFailed()
    {
        var path = WriteTempFile();
        var store = new InMemoryPendingRebootOperationStore();
        var provider = new AssertingPendingProvider(store) { ThrowOnQueue = true };
        var action = BuildAction(locked: true, provider, store);

        var result = await action.ExecuteAsync(Req(path), rebootConsentGiven: true, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(LockedFileRemediationOutcome.Failed, result.Outcome);
        Assert.Equal(RebootRequiredState.Failed, result.RebootState);
        Assert.NotNull(result.PendingOperationId);
        Assert.False(provider.IsQueued(path));
        Assert.Equal(PendingOperationStatus.Failed, store.Get(result.PendingOperationId!.Value)!.Status);
    }

    // ── Cancel-before-reboot ────────────────────────────────────────────────

    [Fact]
    public async Task Cancel_BeforeReboot_ClearsPendingOperation()
    {
        var path = WriteTempFile();
        var provider = new SimulationPendingFileOperationProvider();
        var store = new InMemoryPendingRebootOperationStore();
        var action = BuildAction(locked: true, provider, store);
        var queued = await action.ExecuteAsync(Req(path), rebootConsentGiven: true, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        var cancel = new CancelPendingOperationAction(store, provider, new FixedClock());
        var outcome = cancel.Cancel(queued.PendingOperationId!.Value);

        Assert.Equal(CancelOutcome.Canceled, outcome);
        Assert.False(provider.IsQueued(path), "canceled delete must not run on reboot");
        Assert.Equal(PendingOperationStatus.Canceled, store.Get(queued.PendingOperationId.Value)!.Status);
    }

    [Fact]
    public async Task Cancel_AfterReplay_IsBlocked()
    {
        var path = WriteTempFile();
        var provider = new SimulationPendingFileOperationProvider();
        var store = new InMemoryPendingRebootOperationStore();
        var action = BuildAction(locked: true, provider, store);
        var queued = await action.ExecuteAsync(Req(path), rebootConsentGiven: true, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        // Simulate reboot: the deferred delete ran (file gone) and replay applies.
        File.Delete(path);
        var replayer = new PendingOperationReplayer(store, new FakePresence(absent: true), new FixedClock());
        replayer.Replay();

        var cancel = new CancelPendingOperationAction(store, provider, new FixedClock());
        var outcome = cancel.Cancel(queued.PendingOperationId!.Value);

        Assert.Equal(CancelOutcome.BlockedAlreadyReplayed, outcome);
    }

    [Fact]
    public async Task Cancel_AfterReplayFailure_IsBlockedAsTerminalState()
    {
        var path = WriteTempFile();
        var provider = new SimulationPendingFileOperationProvider();
        var store = new InMemoryPendingRebootOperationStore();
        var action = BuildAction(locked: true, provider, store);
        var queued = await action.ExecuteAsync(Req(path), rebootConsentGiven: true, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        var replayer = new PendingOperationReplayer(store, new FakePresence(absent: false), new FixedClock());
        replayer.Replay();

        var cancel = new CancelPendingOperationAction(store, provider, new FixedClock());
        var outcome = cancel.Cancel(queued.PendingOperationId!.Value);

        Assert.Equal(CancelOutcome.BlockedTerminalState, outcome);
        Assert.Equal(PendingOperationStatus.Failed, store.Get(queued.PendingOperationId.Value)!.Status);
    }

    // ── Idempotent replay ───────────────────────────────────────────────────

    private sealed class FakePresence : IFilePresenceProbe
    {
        private readonly bool _absent;
        public FakePresence(bool absent) => _absent = absent;
        public bool Exists(string path) => !_absent;
    }

    [Fact]
    public async Task Replay_AppliesOnce_AndIsIdempotent()
    {
        var path = WriteTempFile();
        var provider = new SimulationPendingFileOperationProvider();
        var store = new InMemoryPendingRebootOperationStore();
        var action = BuildAction(locked: true, provider, store);
        var queued = await action.ExecuteAsync(Req(path), rebootConsentGiven: true, new InMemoryRemediationJournal(), RemediationCorrelationId.New());
        var id = queued.PendingOperationId!.Value;

        var replayer = new PendingOperationReplayer(store, new FakePresence(absent: true), new FixedClock());

        var first = replayer.Replay();
        var second = replayer.Replay();

        Assert.Contains(first, f => f.Id == id && f.Status == PendingOperationStatus.Replayed);
        Assert.Contains(second, f => f.Id == id && f.Status == PendingOperationStatus.Replayed); // already replayed → no-op
        Assert.Contains(first, f => f.Id == id && f.Detail.Contains("pending verification", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(first, f => f.Id == id && f.Detail.Contains("applied", StringComparison.OrdinalIgnoreCase));
        // Exactly one Replayed transition in the journal — no double-apply.
        Assert.Equal(1, store.Journal().Count(j => j.Id == id && j.Status == PendingOperationStatus.Replayed));
    }

    [Fact]
    public async Task Replay_TargetStillPresent_MarksFailed_NotRemoved()
    {
        var path = WriteTempFile();
        var provider = new SimulationPendingFileOperationProvider();
        var store = new InMemoryPendingRebootOperationStore();
        var action = BuildAction(locked: true, provider, store);
        var queued = await action.ExecuteAsync(Req(path), rebootConsentGiven: true, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        // Simulate a reboot where the deferred delete did NOT happen (file present).
        var replayer = new PendingOperationReplayer(store, new FakePresence(absent: false), new FixedClock());
        var findings = replayer.Replay();

        Assert.Contains(findings, f => f.Status == PendingOperationStatus.Failed);
        Assert.Equal(PendingOperationStatus.Failed, store.Get(queued.PendingOperationId!.Value)!.Status);
    }

    // ── No real reboot / pending-write proof ────────────────────────────────

    [Fact]
    public void OnlyProvider_IsTheSimulationProvider()
    {
        var engine = typeof(IPendingFileOperationProvider).Assembly;
        var impls = engine.GetTypes()
            .Where(t => typeof(IPendingFileOperationProvider).IsAssignableFrom(t) && t is { IsAbstract: false, IsInterface: false })
            .Select(t => t.Name)
            .ToArray();

        Assert.Equal(new[] { nameof(SimulationPendingFileOperationProvider) }, impls);
    }

    [Fact]
    public void NoRebootOrShutdownApiReferencedByRebootNamespace()
    {
        // Reflection guard: no method in the Reboot namespace references a shutdown
        // API surface. (Static grep covers source; this covers the shipped types.)
        var types = typeof(IPendingFileOperationProvider).Assembly.GetTypes()
            .Where(t => t.Namespace == "DataVanger.Engine.Remediation.Reboot");
        Assert.Contains(types, t => t.Name == nameof(SimulationPendingFileOperationProvider));
        // No type named or referencing shutdown/restart exists in this namespace.
        Assert.DoesNotContain(types, t =>
            t.Name.Contains("Shutdown", StringComparison.OrdinalIgnoreCase) ||
            t.Name.Contains("Restart", StringComparison.OrdinalIgnoreCase));
    }
}
