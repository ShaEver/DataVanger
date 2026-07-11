using System.Collections.Generic;
using DataVanger.Shared.Realtime;

namespace DataVanger.Service.Protection;

/// <summary>
/// In-memory sink — primarily a test fixture, but also usable as a
/// default no-op-with-history sink in single-process scenarios.
/// </summary>
public sealed class InMemoryRealtimeProtectionEventSink : IRealtimeProtectionEventSink
{
    private readonly object _gate = new();
    private readonly List<RealtimeProtectionEvent> _events = new();

    public IReadOnlyList<RealtimeProtectionEvent> Snapshot()
    {
        lock (_gate) return _events.ToArray();
    }

    public int Count
    {
        get { lock (_gate) return _events.Count; }
    }

    public void Publish(RealtimeProtectionEvent ev)
    {
        if (ev is null) return;
        lock (_gate) _events.Add(ev);
    }

    public void Clear()
    {
        lock (_gate) _events.Clear();
    }
}
