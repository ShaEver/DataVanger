using System;
using System.Collections.Generic;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Deterministic, network-free, disk-free content sink. Holds the active and
/// last-known-good staged sets per feed in memory. Default sink used by tests
/// and one-process scenarios.
///
/// Models the atomic staging/commit contract: staged content is only promoted
/// to "active" on <see cref="Commit"/>. The prior active set is retained as
/// last-known-good for rollback.
/// </summary>
public sealed class InMemoryUpdateContentSink : IUpdateContentSink
{
    private sealed class FeedContent
    {
        public long ActiveSequence;
        public List<StagedPackage> Active = new();
        public bool HasLastKnownGood;
        public long LastKnownGoodSequence;
        public List<StagedPackage> LastKnownGood = new();
        public List<StagedPackage>? Pending;
        public long PendingSequence;
    }

    private readonly object _gate = new();
    private readonly Dictionary<string, FeedContent> _feeds = new(StringComparer.Ordinal);

    public void Stage(string feedId, long sequence, IReadOnlyList<StagedPackage> packages)
    {
        if (packages is null) throw new ArgumentNullException(nameof(packages));
        lock (_gate)
        {
            var feed = GetOrCreate(feedId);
            feed.Pending = new List<StagedPackage>(packages);
            feed.PendingSequence = sequence;
        }
    }

    public void Commit(string feedId, long sequence)
    {
        lock (_gate)
        {
            var feed = GetOrCreate(feedId);
            if (feed.Pending is null || feed.PendingSequence != sequence)
                throw new InvalidOperationException("No matching staged content to commit.");

            if (feed.ActiveSequence > 0)
            {
                feed.LastKnownGood = feed.Active;
                feed.LastKnownGoodSequence = feed.ActiveSequence;
                feed.HasLastKnownGood = true;
            }

            feed.Active = feed.Pending;
            feed.ActiveSequence = sequence;
            feed.Pending = null;
            feed.PendingSequence = 0;
        }
    }

    public void Restore(string feedId)
    {
        lock (_gate)
        {
            var feed = GetOrCreate(feedId);
            if (!feed.HasLastKnownGood)
                throw new InvalidOperationException("No last-known-good content to restore.");

            feed.Active = feed.LastKnownGood;
            feed.ActiveSequence = feed.LastKnownGoodSequence;
            feed.HasLastKnownGood = false;
            feed.LastKnownGood = new List<StagedPackage>();
            feed.LastKnownGoodSequence = 0;
            feed.Pending = null;
            feed.PendingSequence = 0;
        }
    }

    /// <summary>Test/diagnostic helper: number of active packages for a feed.</summary>
    public int GetActivePackageCount(string feedId)
    {
        lock (_gate)
        {
            return _feeds.TryGetValue(feedId, out var feed) ? feed.Active.Count : 0;
        }
    }

    /// <summary>Test/diagnostic helper: active sequence for a feed (0 when none).</summary>
    public long GetActiveSequence(string feedId)
    {
        lock (_gate)
        {
            return _feeds.TryGetValue(feedId, out var feed) ? feed.ActiveSequence : 0;
        }
    }

    private FeedContent GetOrCreate(string feedId)
    {
        if (!_feeds.TryGetValue(feedId, out var feed))
        {
            feed = new FeedContent();
            _feeds[feedId] = feed;
        }
        return feed;
    }
}
