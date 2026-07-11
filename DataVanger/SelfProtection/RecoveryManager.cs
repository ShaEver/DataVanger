using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace DataVanger.SelfProtection;

/// <summary>
/// Records recovery actions taken by the Self-Protection subsystem.
///
/// The manager is intentionally passive: it does not authorise anything
/// on its own — callers invoke <see cref="Record"/> after performing the
/// underlying operation (e.g. restoring a configuration file from
/// backup). The manager also forwards a <see cref="TamperEvent"/> tagged
/// <see cref="TamperKind.RecoveryActionTaken"/> so the reporting layer
/// can include the action in forensic timelines.
///
/// Bounded by <paramref name="capacity"/> to keep memory flat. Drops the
/// OLDEST action on overflow.
/// </summary>
public sealed class RecoveryManager
{
    private readonly object _gate = new();
    private readonly LinkedList<RecoveryAction> _history = new();
    private readonly ITamperEventSink? _sink;
    private long _recorded;
    private long _dropped;

    public int Capacity { get; }
    public long RecordedCount => Interlocked.Read(ref _recorded);
    public long DroppedCount => Interlocked.Read(ref _dropped);

    public RecoveryManager(ITamperEventSink? sink = null, int capacity = 64)
    {
        _sink = sink;
        Capacity = capacity > 0 ? capacity : 64;
    }

    public RecoveryAction Record(
        string component,
        RecoveryOutcome outcome,
        string description,
        DateTime? nowUtc = null)
    {
        var stamp = nowUtc?.ToUniversalTime() ?? DateTime.UtcNow;
        var action = new RecoveryAction(component, outcome, description, stamp);

        lock (_gate)
        {
            while (_history.Count >= Capacity && _history.First is not null)
            {
                _history.RemoveFirst();
                Interlocked.Increment(ref _dropped);
            }
            _history.AddLast(action);
            Interlocked.Increment(ref _recorded);
        }

        try
        {
            _sink?.Publish(new TamperEvent(
                kind: TamperKind.RecoveryActionTaken,
                severity: outcome == RecoveryOutcome.Failed ? TamperSeverity.Medium : TamperSeverity.Info,
                component: action.Component,
                targetPath: "",
                description: $"Recovery {outcome}: {description}",
                timestampUtc: action.TimestampUtc));
        }
        catch (System.Exception) { /* sink must never crash the recovery path */ }

        return action;
    }

    public IReadOnlyList<RecoveryAction> Snapshot()
    {
        lock (_gate) return _history.ToArray();
    }

    public void Clear()
    {
        lock (_gate) _history.Clear();
    }
}
