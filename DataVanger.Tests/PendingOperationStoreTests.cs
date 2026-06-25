using System;
using System.Linq;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Reboot;
using Xunit;

// Phase 03D — pending-operation store transition + idempotency tests.
public class PendingOperationStoreTests
{
    private static readonly DateTimeOffset T0 = new(2026, 6, 13, 0, 0, 0, TimeSpan.Zero);

    private static PendingRebootOperation Op(PendingOperationId id) => new()
    {
        Id = id,
        Kind = PendingOperationKind.DeleteOnReboot,
        TargetPath = @"C:\Temp\evil.exe",
        CorrelationId = RemediationCorrelationId.New(),
        CancelToken = id.ToString(),
        Status = PendingOperationStatus.Queued,
        CreatedUtc = T0,
        LastUpdatedUtc = T0,
    };

    [Fact]
    public void Add_ThenGet_ReturnsQueuedOperation()
    {
        var store = new InMemoryPendingRebootOperationStore();
        var id = PendingOperationId.New();
        store.Add(Op(id));

        Assert.Equal(PendingOperationStatus.Queued, store.Get(id)!.Status);
        Assert.Single(store.Journal());
    }

    [Fact]
    public void Add_Duplicate_Throws()
    {
        var store = new InMemoryPendingRebootOperationStore();
        var id = PendingOperationId.New();
        store.Add(Op(id));
        Assert.Throws<InvalidOperationException>(() => store.Add(Op(id)));
    }

    [Theory]
    [InlineData(PendingOperationStatus.Canceled, true)]
    [InlineData(PendingOperationStatus.Replayed, true)]
    [InlineData(PendingOperationStatus.Failed, true)]
    [InlineData(PendingOperationStatus.Verified, false)] // can't jump Queued→Verified
    public void Transition_FromQueued_AllowsExpectedTargets(PendingOperationStatus to, bool expected)
    {
        var store = new InMemoryPendingRebootOperationStore();
        var id = PendingOperationId.New();
        store.Add(Op(id));

        Assert.Equal(expected, store.TryTransition(id, to, "x", T0));
    }

    [Fact]
    public void Transition_SameStatus_IsIdempotentNoOp()
    {
        var store = new InMemoryPendingRebootOperationStore();
        var id = PendingOperationId.New();
        store.Add(Op(id));

        Assert.False(store.TryTransition(id, PendingOperationStatus.Queued, "again", T0));
        // No extra journal record beyond the initial Add.
        Assert.Single(store.Journal());
    }

    [Fact]
    public void Transition_TerminalCanceled_CannotChangeFurther()
    {
        var store = new InMemoryPendingRebootOperationStore();
        var id = PendingOperationId.New();
        store.Add(Op(id));
        Assert.True(store.TryTransition(id, PendingOperationStatus.Canceled, "cancel", T0));

        Assert.False(store.TryTransition(id, PendingOperationStatus.Replayed, "too late", T0));
        Assert.Equal(PendingOperationStatus.Canceled, store.Get(id)!.Status);
    }

    [Fact]
    public void Replayed_CanReach_Verified()
    {
        var store = new InMemoryPendingRebootOperationStore();
        var id = PendingOperationId.New();
        store.Add(Op(id));
        store.TryTransition(id, PendingOperationStatus.Replayed, "replay", T0);

        Assert.True(store.TryTransition(id, PendingOperationStatus.Verified, "verified", T0));
        Assert.Equal(2 + 1, store.Journal().Count); // add + replay + verify
    }

    [Fact]
    public void TryTransition_UnknownId_ReturnsFalse()
        => Assert.False(new InMemoryPendingRebootOperationStore()
            .TryTransition(PendingOperationId.New(), PendingOperationStatus.Replayed, "x", T0));
}
