using System;
using System.Collections.Generic;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Deterministic in-memory anti-downgrade state store. Tracks, per feed, the
/// highest accepted sequence + canonical hash (current) and a single
/// last-known-good snapshot for rollback. No disk, no network.
/// </summary>
public sealed class InMemoryUpdateStateStore : IUpdateStateStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, UpdateStateSnapshot> _current = new(StringComparer.Ordinal);
    private readonly Dictionary<string, UpdateStateSnapshot> _lastKnownGood = new(StringComparer.Ordinal);

    public UpdateStateSnapshot GetCurrent(string feedId)
    {
        lock (_gate)
        {
            return _current.TryGetValue(feedId, out var snapshot) ? snapshot : UpdateStateSnapshot.Empty(feedId);
        }
    }

    public UpdateStateSnapshot? GetLastKnownGood(string feedId)
    {
        lock (_gate)
        {
            return _lastKnownGood.TryGetValue(feedId, out var snapshot) ? snapshot : null;
        }
    }

    public void Commit(UpdateStateSnapshot newState)
    {
        if (newState is null) throw new ArgumentNullException(nameof(newState));
        lock (_gate)
        {
            if (_current.TryGetValue(newState.FeedId, out var previous) && previous.HasState)
                _lastKnownGood[newState.FeedId] = previous;
            _current[newState.FeedId] = newState;
        }
    }

    public bool TryRollback(string feedId, out UpdateStateSnapshot restored)
    {
        lock (_gate)
        {
            if (_lastKnownGood.TryGetValue(feedId, out var snapshot))
            {
                _current[feedId] = snapshot;
                _lastKnownGood.Remove(feedId);
                restored = snapshot;
                return true;
            }

            restored = GetCurrentNoLock(feedId);
            return false;
        }
    }

    private UpdateStateSnapshot GetCurrentNoLock(string feedId)
        => _current.TryGetValue(feedId, out var snapshot) ? snapshot : UpdateStateSnapshot.Empty(feedId);
}
