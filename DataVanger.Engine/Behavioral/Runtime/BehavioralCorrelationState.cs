using System;
using System.Collections.Generic;

namespace DataVanger.Engine.Behavioral.Runtime;

/// <summary>
/// Short-lived, bounded record of one tracked process used for behavioral
/// correlation (lineage, command-line context, indicators seen).
/// </summary>
public sealed class TrackedProcess
{
    public int ProcessId { get; init; }
    public int? ParentProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ImagePath { get; set; }
    public string? CommandLine { get; set; }
    public DateTimeOffset FirstSeenUtc { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }

    /// <summary>Distinct conservative indicator tags observed for this process.</summary>
    public HashSet<string> Indicators { get; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Bounded, TTL-cleaned correlation store for the Behavioral Engine
/// Runtime Binding (Phase 2 / Step 06).
///
/// Guarantees:
///   - The number of tracked processes never exceeds MaxTrackedProcesses
///     (oldest-by-last-seen entries are evicted under pressure).
///   - Entries older than the TTL are removed on access (Prune) — no
///     permanent suspicion state survives the TTL window.
///   - All mutation is single-threaded under the binding's lock; this
///     type itself is not internally synchronized.
///   - No background threads, no timers — cleanup is event-driven and
///     deterministic, which keeps tests free of sleeps.
/// </summary>
public sealed class BehavioralCorrelationState
{
    private readonly int _maxTrackedProcesses;
    private readonly TimeSpan _ttl;
    private readonly Dictionary<int, TrackedProcess> _byPid = new();

    /// <summary>Count of entries evicted because the size limit was reached.</summary>
    public long Evictions { get; private set; }

    /// <summary>Count of entries removed by TTL cleanup.</summary>
    public long Expirations { get; private set; }

    public BehavioralCorrelationState(int maxTrackedProcesses, TimeSpan ttl)
    {
        _maxTrackedProcesses = maxTrackedProcesses <= 0 ? 4096 : maxTrackedProcesses;
        _ttl = ttl <= TimeSpan.Zero ? TimeSpan.FromMinutes(10) : ttl;
    }

    public int Count => _byPid.Count;

    /// <summary>
    /// Records or updates a process. Returns the tracked entry. Triggers
    /// TTL pruning first, then enforces the size bound. Returns
    /// <paramref name="evicted"/> = true when the size limit forced an
    /// eviction to make room for a brand-new process.
    /// </summary>
    public TrackedProcess Observe(
        int processId,
        DateTimeOffset nowUtc,
        out bool evicted,
        int? parentProcessId = null,
        string? processName = null,
        string? imagePath = null,
        string? commandLine = null)
    {
        evicted = false;
        Prune(nowUtc);

        if (_byPid.TryGetValue(processId, out var existing))
        {
            existing.LastSeenUtc = nowUtc;
            if (parentProcessId.HasValue) existing.ParentProcessId = parentProcessId;
            if (!string.IsNullOrEmpty(processName)) existing.ProcessName = processName;
            if (!string.IsNullOrEmpty(imagePath)) existing.ImagePath = imagePath;
            if (!string.IsNullOrEmpty(commandLine)) existing.CommandLine = commandLine;
            return existing;
        }

        if (_byPid.Count >= _maxTrackedProcesses)
        {
            EvictOldest();
            evicted = true;
        }

        var entry = new TrackedProcess
        {
            ProcessId = processId,
            ParentProcessId = parentProcessId,
            ProcessName = processName,
            ImagePath = imagePath,
            CommandLine = commandLine,
            FirstSeenUtc = nowUtc,
            LastSeenUtc = nowUtc,
        };
        _byPid[processId] = entry;
        return entry;
    }

    public bool TryGet(int processId, out TrackedProcess process) => _byPid.TryGetValue(processId, out process!);

    /// <summary>Removes entries whose last-seen time is older than the TTL.</summary>
    public void Prune(DateTimeOffset nowUtc)
    {
        if (_byPid.Count == 0) return;
        List<int>? stale = null;
        foreach (var kvp in _byPid)
        {
            if (nowUtc - kvp.Value.LastSeenUtc > _ttl)
            {
                (stale ??= new List<int>()).Add(kvp.Key);
            }
        }
        if (stale is null) return;
        foreach (var pid in stale)
        {
            _byPid.Remove(pid);
            Expirations++;
        }
    }

    public void Clear() => _byPid.Clear();

    private void EvictOldest()
    {
        int oldestPid = 0;
        DateTimeOffset oldest = DateTimeOffset.MaxValue;
        var found = false;
        foreach (var kvp in _byPid)
        {
            if (kvp.Value.LastSeenUtc < oldest)
            {
                oldest = kvp.Value.LastSeenUtc;
                oldestPid = kvp.Key;
                found = true;
            }
        }
        if (found)
        {
            _byPid.Remove(oldestPid);
            Evictions++;
        }
    }
}
