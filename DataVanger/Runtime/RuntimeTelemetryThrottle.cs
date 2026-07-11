using System;
using System.Collections.Generic;

namespace DataVanger.Runtime;

/// <summary>
/// Cheap, lock-protected sliding-window throttle for runtime events.
///
/// ETW providers can emit thousands of events per second. The throttle
/// drops events past a per-(kind, pid) ceiling so a noisy script or a
/// chatty process can't flood the behavioral bus and starve other
/// signals. Drops are counted (<see cref="DroppedCount"/>) so callers
/// can surface a single diagnostic instead of one log line per drop.
///
/// Default budget: 64 events per (kind, pid) per second.
/// </summary>
public sealed class RuntimeTelemetryThrottle
{
    private readonly object _lock = new();
    private readonly Dictionary<(RuntimeTelemetryEventKind, int), Bucket> _buckets = new();
    private readonly int _maxPerWindow;
    private readonly TimeSpan _window;
    private long _allowed;
    private long _dropped;

    public RuntimeTelemetryThrottle(int maxPerWindow = 64, TimeSpan? window = null)
    {
        _maxPerWindow = maxPerWindow > 0 ? maxPerWindow : 64;
        _window = window ?? TimeSpan.FromSeconds(1);
    }

    public long AllowedCount => System.Threading.Interlocked.Read(ref _allowed);
    public long DroppedCount => System.Threading.Interlocked.Read(ref _dropped);
    public int  MaxPerWindow => _maxPerWindow;
    public TimeSpan Window   => _window;

    /// <summary>Returns <c>true</c> if the event is allowed through; <c>false</c> if it was dropped.</summary>
    public bool ShouldAllow(RuntimeTelemetryEvent ev)
    {
        if (ev is null) return false;
        var key = (ev.Kind, ev.Pid);
        var now = ev.TimestampUtc == default ? DateTime.UtcNow : ev.TimestampUtc;

        lock (_lock)
        {
            if (!_buckets.TryGetValue(key, out var bucket))
            {
                bucket = new Bucket { WindowStartUtc = now, Count = 0 };
                _buckets[key] = bucket;
            }
            if (now - bucket.WindowStartUtc > _window)
            {
                bucket.WindowStartUtc = now;
                bucket.Count = 0;
            }
            if (bucket.Count >= _maxPerWindow)
            {
                System.Threading.Interlocked.Increment(ref _dropped);
                return false;
            }
            bucket.Count++;
        }
        System.Threading.Interlocked.Increment(ref _allowed);
        return true;
    }

    /// <summary>Drop stale buckets so the dictionary doesn't grow unbounded.</summary>
    public int Prune(int maxBuckets = 1024)
    {
        if (maxBuckets <= 0) maxBuckets = 1024;
        lock (_lock)
        {
            if (_buckets.Count <= maxBuckets) return 0;
            // Remove oldest entries first.
            var ordered = new List<KeyValuePair<(RuntimeTelemetryEventKind, int), Bucket>>(_buckets);
            ordered.Sort((a, b) => a.Value.WindowStartUtc.CompareTo(b.Value.WindowStartUtc));
            int toRemove = ordered.Count - maxBuckets;
            for (int i = 0; i < toRemove; i++)
            {
                _buckets.Remove(ordered[i].Key);
            }
            return toRemove;
        }
    }

    private sealed class Bucket
    {
        public DateTime WindowStartUtc;
        public int Count;
    }
}
