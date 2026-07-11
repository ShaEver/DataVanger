using System;
using System.Collections.Generic;
using DataVanger.Shared.ProtectedFiles;

namespace DataVanger.Engine.ProtectedFiles;

/// <summary>
/// Bounded, TTL-cleaned correlation store for the Protected Files
/// Activity Monitor (Phase 2 / Step 07). Tracks one
/// <see cref="ProtectedFilesActivityState"/> per correlation key
/// (process).
///
/// Guarantees (mirroring the behavioral runtime binding's bounded state):
///   - The number of tracked keys never exceeds MaxTrackedProcesses
///     (oldest-by-last-seen entries are evicted under pressure).
///   - Entries older than the TTL are removed on access (Prune) — no
///     permanent suspicion state survives the TTL window.
///   - All mutation is single-threaded under the monitor's lock; this
///     type itself is not internally synchronized.
///   - No background threads, no timers — cleanup is event-driven and
///     deterministic, which keeps tests free of sleeps.
/// </summary>
public sealed class ActivityTracker
{
    private readonly ProtectedFilesActivityOptions _options;
    private readonly Dictionary<string, ProtectedFilesActivityState> _byKey =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Count of entries evicted because the size limit was reached.</summary>
    public long Evictions { get; private set; }

    /// <summary>Count of entries removed by TTL cleanup.</summary>
    public long Expirations { get; private set; }

    public ActivityTracker(ProtectedFilesActivityOptions options)
    {
        _options = (options ?? ProtectedFilesActivityOptions.DevelopmentSafe()).WithSafeDefaults();
    }

    public int Count => _byKey.Count;

    /// <summary>Total distinct directories tracked across all current states.</summary>
    public int TotalTrackedDirectories
    {
        get
        {
            var total = 0;
            foreach (var state in _byKey.Values) total += state.MutationProfile.DistinctDirectoryCount;
            return total;
        }
    }

    /// <summary>
    /// Gets or creates the state for a correlation key. Prunes TTL-expired
    /// entries first, then enforces the size bound. Sets
    /// <paramref name="evicted"/> = true when the size limit forced an
    /// eviction to make room for a brand-new key.
    /// </summary>
    public ProtectedFilesActivityState GetOrCreate(string correlationKey, DateTimeOffset nowUtc, out bool evicted)
    {
        evicted = false;
        Prune(nowUtc);

        if (_byKey.TryGetValue(correlationKey, out var existing))
        {
            existing.LastSeenUtc = nowUtc;
            return existing;
        }

        if (_byKey.Count >= _options.MaxTrackedProcesses)
        {
            EvictOldest();
            evicted = true;
        }

        var state = new ProtectedFilesActivityState(
            correlationKey,
            _options.ActivityWindow,
            _options.MaxWindowSamples,
            _options.MaxTrackedDirectories,
            _options.MaxTrackedExtensionTransitions,
            nowUtc);
        _byKey[correlationKey] = state;
        return state;
    }

    public bool TryGet(string correlationKey, out ProtectedFilesActivityState state)
        => _byKey.TryGetValue(correlationKey, out state!);

    /// <summary>Removes entries whose last-seen time is older than the TTL.</summary>
    public void Prune(DateTimeOffset nowUtc)
    {
        if (_byKey.Count == 0) return;
        List<string>? stale = null;
        foreach (var kvp in _byKey)
        {
            if (nowUtc - kvp.Value.LastSeenUtc > _options.ProcessStateTtl)
            {
                (stale ??= new List<string>()).Add(kvp.Key);
            }
        }
        if (stale is null) return;
        foreach (var key in stale)
        {
            _byKey.Remove(key);
            Expirations++;
        }
    }

    public void Clear() => _byKey.Clear();

    private void EvictOldest()
    {
        string? oldestKey = null;
        DateTimeOffset oldest = DateTimeOffset.MaxValue;
        foreach (var kvp in _byKey)
        {
            if (kvp.Value.LastSeenUtc < oldest)
            {
                oldest = kvp.Value.LastSeenUtc;
                oldestKey = kvp.Key;
            }
        }
        if (oldestKey is not null)
        {
            _byKey.Remove(oldestKey);
            Evictions++;
        }
    }
}
