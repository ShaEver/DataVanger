using System;
using System.Collections.Generic;

namespace DataVanger.Engine.ProtectedFiles;

/// <summary>
/// A bounded, sliding count of events over a fixed time window for the
/// Protected Files Activity Monitor (Phase 2 / Step 07).
///
/// Guarantees:
///   - Retained timestamps never exceed <c>maxSamples</c>; once the cap
///     is hit the oldest sample is dropped (the window therefore reports
///     "at least the cap" rather than growing without bound).
///   - Pruning is event-driven and deterministic with an injected clock —
///     no timers, no background threads, no sleeps in tests.
/// </summary>
public sealed class ActivityWindow
{
    private readonly TimeSpan _window;
    private readonly int _maxSamples;
    private readonly Queue<DateTimeOffset> _samples = new();

    /// <summary>Total events ever recorded (saturating view; advisory only).</summary>
    public long TotalRecorded { get; private set; }

    public ActivityWindow(TimeSpan window, int maxSamples)
    {
        _window = window <= TimeSpan.Zero ? TimeSpan.FromSeconds(30) : window;
        _maxSamples = maxSamples < 1 ? 4096 : maxSamples;
    }

    /// <summary>Current count of events inside the sliding window (after pruning).</summary>
    public int CountInWindow(DateTimeOffset nowUtc)
    {
        Prune(nowUtc);
        return _samples.Count;
    }

    /// <summary>Records an event at the supplied time and returns the in-window count.</summary>
    public int Record(DateTimeOffset nowUtc)
    {
        TotalRecorded++;
        _samples.Enqueue(nowUtc);
        // Bound memory: drop the oldest sample once over the cap.
        while (_samples.Count > _maxSamples)
        {
            _samples.Dequeue();
        }
        Prune(nowUtc);
        return _samples.Count;
    }

    /// <summary>Removes samples that fell out of the sliding window.</summary>
    public void Prune(DateTimeOffset nowUtc)
    {
        var cutoff = nowUtc - _window;
        while (_samples.Count > 0 && _samples.Peek() < cutoff)
        {
            _samples.Dequeue();
        }
    }

    public void Clear() => _samples.Clear();
}
