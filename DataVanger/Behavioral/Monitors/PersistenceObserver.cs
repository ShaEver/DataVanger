using System;
using System.Collections.Generic;

namespace DataVanger.Behavioral.Monitors;

/// <summary>
/// Glue that turns the existing static persistence snapshot
/// (<see cref="DataVanger.Engine.PersistenceCollector"/>) into a stream
/// of behavioral events.
///
/// On each <see cref="Refresh"/> call we diff the current persistence
/// set against the last snapshot and publish a
/// <see cref="BehavioralEventKind.PersistenceCreated"/> event for every
/// new entry. This lets the correlation engine match new persistence
/// against recent file drops without coupling the behavioral engine to
/// registry APIs directly.
/// </summary>
public sealed class PersistenceObserver
{
    private readonly IBehavioralEventBus _bus;
    private readonly object _sync = new();
    private HashSet<string> _last = new(StringComparer.OrdinalIgnoreCase);
    public int LastSeenCount { get; private set; }

    public PersistenceObserver(IBehavioralEventBus bus)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
    }

    /// <summary>Push the latest persistence snapshot. Returns the number of new entries published.</summary>
    public int Refresh(IEnumerable<string> currentPersistencePaths, int observerPid = 0)
    {
        if (currentPersistencePaths is null) return 0;
        var current = new HashSet<string>(currentPersistencePaths, StringComparer.OrdinalIgnoreCase);
        int published = 0;
        lock (_sync)
        {
            foreach (var path in current)
            {
                if (_last.Contains(path)) continue;
                _bus.Publish(new BehavioralEvent(
                    kind: BehavioralEventKind.PersistenceCreated,
                    pid: observerPid,
                    parentPid: 0,
                    processName: "",
                    imagePath: "",
                    commandLine: "",
                    targetPath: path,
                    extraTag: "persistence",
                    severity: BehavioralSeverity.Medium,
                    description: $"Nova entrada de persistência detectada: {path}",
                    timestampUtc: DateTime.UtcNow));
                published++;
            }
            _last = current;
            LastSeenCount = current.Count;
        }
        return published;
    }
}
