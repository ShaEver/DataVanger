using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Engine.RuntimeEvents;

/// <summary>
/// Deterministic in-memory consumer for tests and one-process
/// scenarios. Records every delivered event in publication order so
/// tests can assert exact counts, ordering, and content without
/// background threads.
/// </summary>
public sealed class CollectingRuntimeEventConsumer : IRuntimeEventConsumer
{
    private readonly object _gate = new();
    private readonly List<RuntimeSecurityEvent> _events = new();

    public int Count
    {
        get { lock (_gate) return _events.Count; }
    }

    public IReadOnlyList<RuntimeSecurityEvent> Snapshot()
    {
        lock (_gate) return _events.ToArray();
    }

    public void Clear()
    {
        lock (_gate) _events.Clear();
    }

    public ValueTask HandleAsync(RuntimeSecurityEvent runtimeEvent, CancellationToken cancellationToken = default)
    {
        if (runtimeEvent is null) return ValueTask.CompletedTask;
        lock (_gate) _events.Add(runtimeEvent);
        return ValueTask.CompletedTask;
    }
}
