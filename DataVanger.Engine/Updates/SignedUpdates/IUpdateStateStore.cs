using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Persists per-feed update state: the highest accepted manifest sequence and
/// its canonical hash (for anti-downgrade), plus a last-known-good snapshot
/// (for rollback). Implementations must never reach the network.
/// </summary>
public interface IUpdateStateStore
{
    /// <summary>Current accepted state for the feed (Empty when none).</summary>
    UpdateStateSnapshot GetCurrent(string feedId);

    /// <summary>Last-known-good snapshot for the feed, or null when none.</summary>
    UpdateStateSnapshot? GetLastKnownGood(string feedId);

    /// <summary>
    /// Commit a newly accepted state. The previously-current state (if any)
    /// becomes the new last-known-good.
    /// </summary>
    void Commit(UpdateStateSnapshot newState);

    /// <summary>
    /// Restore the last-known-good snapshot as current. Returns true and the
    /// restored snapshot when a last-known-good existed; false otherwise (the
    /// current state is then left unchanged).
    /// </summary>
    bool TryRollback(string feedId, out UpdateStateSnapshot restored);
}
