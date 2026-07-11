using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace DataVanger.SelfProtection;

/// <summary>
/// Bounded in-memory tamper-event sink.
///
/// Keeps the most recent <c>capacity</c> events; drops the OLDEST on
/// overflow so callers always see fresh data — important for forensic
/// reporting under flooding.
///
/// The sink is intentionally synchronous and thread-safe via a single
/// lock. It never spawns background threads, never holds resources past
/// disposal, and never throws out of <see cref="Publish"/>.
/// </summary>
public sealed class InMemoryTamperEventSink : ITamperEventSink, IDisposable
{
    private readonly object _gate = new();
    private readonly LinkedList<TamperEvent> _events = new();
    private long _published;
    private long _dropped;
    private int _disposed;

    public int Capacity { get; }
    public long PublishedCount => Interlocked.Read(ref _published);
    public long DroppedCount => Interlocked.Read(ref _dropped);

    public InMemoryTamperEventSink(int capacity = 256)
    {
        Capacity = capacity > 0 ? capacity : 256;
    }

    public bool Publish(TamperEvent ev)
    {
        if (ev is null) return false;
        if (Volatile.Read(ref _disposed) == 1) return false;
        lock (_gate)
        {
            while (_events.Count >= Capacity && _events.First is not null)
            {
                _events.RemoveFirst();
                Interlocked.Increment(ref _dropped);
            }
            _events.AddLast(ev);
            Interlocked.Increment(ref _published);
        }
        return true;
    }

    /// <summary>Snapshot the retained events in chronological order.</summary>
    public IReadOnlyList<TamperEvent> Snapshot()
    {
        if (Volatile.Read(ref _disposed) == 1) return Array.Empty<TamperEvent>();
        lock (_gate)
        {
            return _events.ToArray();
        }
    }

    /// <summary>Clear all retained events. Counters are not reset.</summary>
    public void Clear()
    {
        lock (_gate) _events.Clear();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        Clear();
    }
}
