using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.Reporting.Forensics;

/// <summary>
/// Deterministic, append-only timeline of forensic events.
///
/// The timeline accepts events in arbitrary order from concurrent
/// producers and exposes them sorted by timestamp. Ties on the same UTC
/// instant (common when events are synthesised from a single scan
/// snapshot) are broken by insertion order so the result is fully
/// deterministic — required by the reporting tests.
///
/// Anti-FP contract: timelines never reclassify events. They only
/// re-arrange and present them.
/// </summary>
public sealed class ForensicTimeline
{
    private readonly object _sync = new();
    private readonly List<(long Seq, TimelineEvent Event)> _events = new();
    private long _seq;

    public int Count
    {
        get
        {
            lock (_sync) return _events.Count;
        }
    }

    public void Add(TimelineEvent evt)
    {
        if (evt == null) return;
        lock (_sync)
        {
            _events.Add((++_seq, evt));
        }
    }

    public void AddRange(IEnumerable<TimelineEvent> events)
    {
        if (events == null) return;
        foreach (var evt in events) Add(evt);
    }

    public IReadOnlyList<TimelineEvent> Ordered()
    {
        lock (_sync)
        {
            return _events
                .OrderBy(t => t.Event.TimestampUtc)
                .ThenBy(t => t.Seq)
                .Select(t => t.Event)
                .ToList();
        }
    }

    public IReadOnlyList<TimelineEvent> Between(DateTime fromUtc, DateTime toUtc)
    {
        var from = fromUtc.ToUniversalTime();
        var to = toUtc.ToUniversalTime();
        return Ordered()
            .Where(e => e.TimestampUtc >= from && e.TimestampUtc <= to)
            .ToList();
    }

    public IReadOnlyList<TimelineEvent> ForProcess(int processId) =>
        Ordered().Where(e => e.ProcessId == processId).ToList();

    public IReadOnlyList<TimelineEvent> ForCorrelation(string correlationId)
    {
        if (string.IsNullOrEmpty(correlationId)) return System.Array.Empty<TimelineEvent>();
        return Ordered()
            .Where(e => string.Equals(e.CorrelationId, correlationId, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }
}
