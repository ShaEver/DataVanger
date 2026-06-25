using System;
using System.Collections.Generic;
using DataVanger.Shared.Realtime;

namespace DataVanger.Service.Realtime;

/// <summary>
/// Deterministic, tick-driven debounce/coalesce layer.
///
/// Behavior:
///   - Groups events by normalized full path (case-insensitive).
///   - Retains the latest event per path; rename folds the OLD path
///     into the NEW path so a rename + change does not double-scan.
///   - Delete cancels any pending entry for that path.
///   - <see cref="Drain"/> returns every entry whose latest event is
///     older than the debounce window — callers drive the wall-clock
///     externally (via the injected utcNow), so tests can use a fake
///     clock and never rely on real sleeps.
///
/// The debouncer holds no background threads.
/// </summary>
public sealed class RealtimeEventDebouncer
{
    private readonly object _gate = new();
    private readonly Dictionary<string, RealtimeFileEvent> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly TimeSpan _window;

    public RealtimeEventDebouncer(TimeSpan window, Func<DateTimeOffset>? utcNow = null)
    {
        if (window <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(window));
        _window = window;
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    public int PendingCount
    {
        get { lock (_gate) return _pending.Count; }
    }

    public void Submit(RealtimeFileEvent ev)
    {
        if (ev is null || string.IsNullOrWhiteSpace(ev.Path)) return;

        lock (_gate)
        {
            // Delete cancels any pending scan: there is nothing to scan.
            if (ev.Kind == RealtimeFileEventKind.Deleted)
            {
                _pending.Remove(ev.Path);
                return;
            }

            // Rename: drop the OLD path's pending entry and keep the
            // newest event under the NEW path key.
            if (ev.Kind == RealtimeFileEventKind.Renamed
                && !string.IsNullOrEmpty(ev.OldPath))
            {
                _pending.Remove(ev.OldPath);
            }

            _pending[ev.Path] = ev;
        }
    }

    /// <summary>
    /// Returns every pending event whose timestamp is older than the
    /// debounce window relative to the injected clock. Drained entries
    /// are removed from the pending set.
    /// </summary>
    public List<RealtimeFileEvent> Drain()
    {
        var now = _utcNow();
        var drained = new List<RealtimeFileEvent>();
        lock (_gate)
        {
            if (_pending.Count == 0) return drained;
            List<string>? toRemove = null;
            foreach (var kv in _pending)
            {
                if (now - kv.Value.TimestampUtc >= _window)
                {
                    drained.Add(kv.Value);
                    (toRemove ??= new List<string>()).Add(kv.Key);
                }
            }
            if (toRemove is not null)
            {
                foreach (var k in toRemove) _pending.Remove(k);
            }
        }
        return drained;
    }

    public void Clear()
    {
        lock (_gate) _pending.Clear();
    }
}
