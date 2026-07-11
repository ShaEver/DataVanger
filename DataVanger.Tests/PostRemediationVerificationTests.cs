using System;
using System.Collections.Generic;
using System.Linq;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Reboot;
using DataVanger.Engine.Remediation.Verification;
using Xunit;

// Phase 03D — post-remediation verification tests. Verification can never report
// clean while any artifact remains.
public class PostRemediationVerificationTests
{
    private sealed class Probes : IFileAbsenceProbe, IPersistenceAbsenceProbe, IQuarantineValidityProbe, IScanCleanProbe
    {
        public bool FileAbsent { get; init; } = true;
        public bool PersistenceGone { get; init; } = true;
        public bool QuarantineValid { get; init; } = true;
        public bool ScanClean { get; init; } = true;

        bool IFileAbsenceProbe.IsAbsent(string path) => FileAbsent;
        bool IPersistenceAbsenceProbe.IsGone(string identity) => PersistenceGone;
        bool IQuarantineValidityProbe.IsValid(string quarantineId) => QuarantineValid;
        bool IScanCleanProbe.IsClean(string target) => ScanClean;
    }

    private static RemediationVerificationService Build(Probes p) => new(p, p, p, p);

    private static readonly DateTimeOffset T0 = new(2026, 6, 13, 0, 0, 0, TimeSpan.Zero);

    private static readonly IReadOnlyList<VerificationCheck> AllChecks = new[]
    {
        new VerificationCheck(VerificationCheckKind.FileAbsent, @"C:\Temp\evil.exe"),
        new VerificationCheck(VerificationCheckKind.PersistenceGone, @"HKCU\...\Run\Evil"),
        new VerificationCheck(VerificationCheckKind.QuarantineRecordValid, "qid-1"),
        new VerificationCheck(VerificationCheckKind.ScanClean, @"C:\Temp"),
    };

    private static PendingOperationId AddReplayedOperation(InMemoryPendingRebootOperationStore store)
    {
        var id = PendingOperationId.New();
        store.Add(new PendingRebootOperation
        {
            Id = id,
            Kind = PendingOperationKind.DeleteOnReboot,
            TargetPath = @"C:\Temp\evil.exe",
            CorrelationId = RemediationCorrelationId.New(),
            CancelToken = id.ToString(),
            Status = PendingOperationStatus.Queued,
            CreatedUtc = T0,
            LastUpdatedUtc = T0,
        });
        store.TryTransition(id, PendingOperationStatus.Replayed, "replay observed absence", T0.AddSeconds(1));
        return id;
    }

    [Fact]
    public void AllChecksPass_IsClean()
    {
        var result = Build(new Probes()).Verify(AllChecks);

        Assert.True(result.IsClean);
        Assert.False(result.HasRemainingArtifact);
        Assert.Empty(result.Failures);
    }

    [Fact]
    public void FileStillPresent_IsNotClean_ReportsRemainingArtifact()
    {
        var result = Build(new Probes { FileAbsent = false }).Verify(AllChecks);

        Assert.False(result.IsClean);
        Assert.True(result.HasRemainingArtifact);
        Assert.Contains(result.Failures, f => f.Kind == VerificationCheckKind.FileAbsent);
    }

    [Fact]
    public void PersistenceRemains_IsNotClean()
    {
        var result = Build(new Probes { PersistenceGone = false }).Verify(AllChecks);
        Assert.False(result.IsClean);
        Assert.Contains(result.Failures, f => f.Kind == VerificationCheckKind.PersistenceGone);
    }

    [Fact]
    public void ScanDirty_IsNotClean()
    {
        var result = Build(new Probes { ScanClean = false }).Verify(AllChecks);
        Assert.False(result.IsClean);
        Assert.Contains(result.Failures, f => f.Kind == VerificationCheckKind.ScanClean);
    }

    [Fact]
    public void QuarantineRecordInvalid_IsNotClean()
    {
        var result = Build(new Probes { QuarantineValid = false }).Verify(AllChecks);
        Assert.False(result.IsClean);
        Assert.Contains(result.Failures, f => f.Kind == VerificationCheckKind.QuarantineRecordValid);
    }

    [Fact]
    public void EmptyCheckList_IsNotClean()
    {
        // No checks performed cannot be asserted as "clean".
        var result = Build(new Probes()).Verify(System.Array.Empty<VerificationCheck>());
        Assert.False(result.IsClean);
    }

    [Fact]
    public void PendingOperationVerification_ReplayedClean_MarksVerified()
    {
        var store = new InMemoryPendingRebootOperationStore();
        var id = AddReplayedOperation(store);
        var action = new PendingOperationVerificationAction(store, Build(new Probes()));

        var result = action.Verify(id, AllChecks);

        Assert.Equal(PendingOperationVerificationOutcome.Verified, result.Outcome);
        Assert.Equal(PendingOperationStatus.Verified, store.Get(id)!.Status);
        Assert.True(result.Verification!.IsClean);
    }

    [Fact]
    public void PendingOperationVerification_WhenArtifactRemains_MarksFailed()
    {
        var store = new InMemoryPendingRebootOperationStore();
        var id = AddReplayedOperation(store);
        var action = new PendingOperationVerificationAction(store, Build(new Probes { FileAbsent = false }));

        var result = action.Verify(id, AllChecks);

        Assert.Equal(PendingOperationVerificationOutcome.Failed, result.Outcome);
        Assert.Equal(PendingOperationStatus.Failed, store.Get(id)!.Status);
        Assert.False(result.Verification!.IsClean);
        Assert.Contains(result.Verification.Failures, f => f.Kind == VerificationCheckKind.FileAbsent);
    }

    [Fact]
    public void PendingOperationVerification_EmptyCheckList_MarksFailed()
    {
        var store = new InMemoryPendingRebootOperationStore();
        var id = AddReplayedOperation(store);
        var action = new PendingOperationVerificationAction(store, Build(new Probes()));

        var result = action.Verify(id, Array.Empty<VerificationCheck>());

        Assert.Equal(PendingOperationVerificationOutcome.Failed, result.Outcome);
        Assert.Equal(PendingOperationStatus.Failed, store.Get(id)!.Status);
        Assert.False(result.Verification!.IsClean);
        Assert.Contains("No verification checks", result.Detail);
    }

    [Fact]
    public void PendingOperationVerification_BlocksQueuedOperation()
    {
        var store = new InMemoryPendingRebootOperationStore();
        var id = PendingOperationId.New();
        store.Add(new PendingRebootOperation
        {
            Id = id,
            Kind = PendingOperationKind.DeleteOnReboot,
            TargetPath = @"C:\Temp\evil.exe",
            CorrelationId = RemediationCorrelationId.New(),
            CancelToken = id.ToString(),
            Status = PendingOperationStatus.Queued,
            CreatedUtc = T0,
            LastUpdatedUtc = T0,
        });
        var action = new PendingOperationVerificationAction(store, Build(new Probes()));

        var result = action.Verify(id, AllChecks);

        Assert.Equal(PendingOperationVerificationOutcome.BlockedNotReplayed, result.Outcome);
        Assert.Equal(PendingOperationStatus.Queued, store.Get(id)!.Status);
    }
}
