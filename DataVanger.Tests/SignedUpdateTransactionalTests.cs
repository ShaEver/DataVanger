using System;
using System.Collections.Generic;
using DataVanger.Engine.Updates.SignedUpdates;
using DataVanger.Shared.Updates;
using Xunit;

namespace DataVanger.Tests;

public sealed class SignedUpdateTransactionalTests
{
    [Fact]
    public void Rollback_ContentFailure_NeverChangesStateOrReportsCompleted()
    {
        const string feed = "tx-feed";
        var state = new InMemoryUpdateStateStore();
        state.Commit(Snapshot(feed, 1));
        state.Commit(Snapshot(feed, 2));
        var service = new SignedUpdateService(
            new UpdatePolicy { Mode = UpdateMode.AutoApplyFeedsOnly, FeedId = feed },
            new SignedManifestVerifier(Array.Empty<PinnedPublicKey>()),
            new UpdatePackageVerifier(), state, new FailingRestoreSink(), new InMemoryUpdateTransport(null));

        var result = service.Rollback();

        Assert.False(result.Succeeded);
        Assert.NotEqual(UpdateResultKind.RollbackCompleted, result.Kind);
        Assert.Equal(2, state.GetCurrent(feed).HighestSequence);
        Assert.Equal(1, state.GetLastKnownGood(feed)!.HighestSequence);
    }

    private static UpdateStateSnapshot Snapshot(string feed, long sequence) => new()
    {
        FeedId = feed,
        HighestSequence = sequence,
        ManifestCanonicalSha256 = new string(sequence == 1 ? 'A' : 'B', 64),
        AppliedUtc = "2026-01-01T00:00:00Z",
    };

    private sealed class FailingRestoreSink : IUpdateContentSink
    {
        public void Stage(string feedId, long sequence, string canonicalManifestSha256, IReadOnlyList<StagedPackage> packages) { }
        public void Commit(string feedId, long sequence) { }
        public void Restore(string feedId) => throw new InvalidOperationException("injected restore failure");
    }
}
