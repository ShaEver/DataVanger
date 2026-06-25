using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;

namespace DataVanger.Behavioral;

/// <summary>
/// Sliding-window in-memory timeline of behavioral events.
///
/// The timeline is bounded by:
///   - a maximum number of retained events (<see cref="Capacity"/>),
///   - a retention window (<see cref="RetentionWindow"/>).
///
/// Older events are pruned lazily during writes/queries. This keeps the
/// engine memory-stable under long runtime — the spec explicitly
/// requires "expire old events" / "prune low-value telemetry".
///
/// Reads are best-effort snapshots — they may miss in-flight events
/// added concurrently with a query. Rules tolerate this by re-querying
/// when they need an authoritative answer.
/// </summary>
public sealed class BehavioralTimeline
{
    private readonly LinkedList<BehavioralEvent> _events = new();
    private readonly object _sync = new();
    public int Capacity { get; }
    public TimeSpan RetentionWindow { get; }

    public BehavioralTimeline(int capacity = 4096, TimeSpan? retention = null)
    {
        Capacity = capacity > 0 ? capacity : 4096;
        RetentionWindow = retention ?? TimeSpan.FromMinutes(5);
    }

    public int Count
    {
        get { lock (_sync) return _events.Count; }
    }

    public void Record(BehavioralEvent ev)
    {
        if (ev is null) return;
        lock (_sync)
        {
            _events.AddLast(ev);
            Prune();
        }
    }

    public IReadOnlyList<BehavioralEvent> Snapshot()
    {
        lock (_sync)
        {
            Prune();
            return _events.ToArray();
        }
    }

    /// <summary>Events for a single pid within the retention window.</summary>
    public IReadOnlyList<BehavioralEvent> ForPid(int pid)
    {
        lock (_sync)
        {
            Prune();
            return _events.Where(e => e.Pid == pid).ToArray();
        }
    }

    /// <summary>Events for an entire process tree, given an ancestry view.</summary>
    public IReadOnlyList<BehavioralEvent> ForProcessTree(int rootPid, ProcessAncestry ancestry)
    {
        lock (_sync)
        {
            Prune();
            var result = new List<BehavioralEvent>();
            foreach (var ev in _events)
            {
                if (ev.Pid == rootPid) { result.Add(ev); continue; }
                if (ancestry.HasAncestorNamed(ev.Pid, "") /* never matches but keeps signature stable */) { /* no-op */ }
                if (IsInTree(ev.Pid, rootPid, ancestry)) result.Add(ev);
            }
            return result;
        }
    }

    /// <summary>Events in a short time-window around <paramref name="anchor"/>.</summary>
    public IReadOnlyList<BehavioralEvent> Around(DateTime anchor, TimeSpan window)
    {
        DateTime min = anchor.ToUniversalTime() - window;
        DateTime max = anchor.ToUniversalTime() + window;
        lock (_sync)
        {
            Prune();
            return _events.Where(e => e.TimestampUtc >= min && e.TimestampUtc <= max).ToArray();
        }
    }

    private static bool IsInTree(int childPid, int rootPid, ProcessAncestry ancestry)
    {
        foreach (var rec in ancestry.Ancestors(childPid, maxDepth: 12))
            if (rec.Pid == rootPid) return true;
        return false;
    }

    private void Prune()
    {
        DateTime cutoff = DateTime.UtcNow - RetentionWindow;
        while (_events.Count > 0)
        {
            var first = _events.First!;
            if (first.Value.TimestampUtc >= cutoff && _events.Count <= Capacity) break;
            _events.RemoveFirst();
        }
    }
}
