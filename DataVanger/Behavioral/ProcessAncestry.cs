using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace DataVanger.Behavioral;

/// <summary>
/// Tracks the live set of processes observed by the behavioral engine and
/// the parent-child relationships between them.
///
/// The engine intentionally does NOT use OS-level snapshots after the
/// initial seed — it builds its view from the event stream so it stays
/// consistent with the rules' worldview. <see cref="Seed"/> can be used
/// at startup to backfill from a <see cref="System.Diagnostics.Process"/>
/// scan.
///
/// Memory is bounded by <see cref="MaxRetainedEnded"/> — terminated
/// processes older than the retention window are pruned.
/// </summary>
public sealed class ProcessAncestry
{
    private readonly ConcurrentDictionary<int, ProcessRecord> _live = new();
    private readonly ConcurrentDictionary<int, ProcessRecord> _ended = new();
    private readonly int _maxRetainedEnded;

    public int LiveCount => _live.Count;
    public int EndedCount => _ended.Count;
    public int MaxRetainedEnded => _maxRetainedEnded;

    public ProcessAncestry(int maxRetainedEnded = 512)
    {
        _maxRetainedEnded = Math.Max(32, maxRetainedEnded);
    }

    /// <summary>Register or update a process record (idempotent).</summary>
    public ProcessRecord Track(int pid, int parentPid, string processName, string imagePath, string commandLine, DateTime startUtc)
    {
        var record = _live.AddOrUpdate(pid,
            _ => new ProcessRecord(pid, parentPid, processName, imagePath, commandLine, startUtc),
            (_, existing) =>
            {
                existing.ParentPid = existing.ParentPid == 0 ? parentPid : existing.ParentPid;
                if (string.IsNullOrEmpty(existing.ProcessName)) existing.ProcessName = processName ?? "";
                if (string.IsNullOrEmpty(existing.ImagePath)) existing.ImagePath = imagePath ?? "";
                if (string.IsNullOrEmpty(existing.CommandLine) && !string.IsNullOrEmpty(commandLine)) existing.CommandLine = commandLine;
                return existing;
            });
        return record;
    }

    /// <summary>Mark a process as terminated. The record is retained for a short window so post-mortem correlation can succeed.</summary>
    public void MarkEnded(int pid, DateTime whenUtc)
    {
        if (_live.TryRemove(pid, out var record))
        {
            record.EndedUtc = whenUtc == default ? DateTime.UtcNow : whenUtc.ToUniversalTime();
            _ended[pid] = record;
        }
        // Bound the ended pool — drop oldest if necessary.
        if (_ended.Count > _maxRetainedEnded) PruneOldEnded();
    }

    public bool TryGet(int pid, out ProcessRecord record)
    {
        if (_live.TryGetValue(pid, out var r) || _ended.TryGetValue(pid, out r))
        {
            record = r;
            return true;
        }
        record = null!;
        return false;
    }

    /// <summary>Walk ancestors from the given pid up the tree. Order: child first.</summary>
    public IEnumerable<ProcessRecord> Ancestors(int pid, int maxDepth = 8)
    {
        var visited = new HashSet<int>();
        int current = pid;
        for (int i = 0; i < maxDepth; i++)
        {
            if (!visited.Add(current)) yield break;
            if (!TryGet(current, out var rec)) yield break;
            yield return rec;
            if (rec.ParentPid <= 0 || rec.ParentPid == current) yield break;
            current = rec.ParentPid;
        }
    }

    /// <summary>Return true when <paramref name="ancestorName"/> appears anywhere in the ancestor chain.</summary>
    public bool HasAncestorNamed(int pid, string ancestorName, int maxDepth = 8)
    {
        if (string.IsNullOrWhiteSpace(ancestorName)) return false;
        foreach (var rec in Ancestors(pid, maxDepth))
        {
            if (rec.ProcessName.Equals(ancestorName, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private void PruneOldEnded()
    {
        // Cheap pruning: drop entries older than the median, capped at maxRetainedEnded.
        var snapshot = _ended.Values.OrderBy(r => r.EndedUtc).ToList();
        int toDrop = Math.Max(0, snapshot.Count - _maxRetainedEnded);
        for (int i = 0; i < toDrop; i++)
            _ended.TryRemove(snapshot[i].Pid, out _);
    }
}

public sealed class ProcessRecord
{
    public ProcessRecord(int pid, int parentPid, string processName, string imagePath, string commandLine, DateTime startUtc)
    {
        Pid = pid;
        ParentPid = parentPid;
        ProcessName = processName ?? "";
        ImagePath = imagePath ?? "";
        CommandLine = commandLine ?? "";
        StartedUtc = startUtc == default ? DateTime.UtcNow : startUtc.ToUniversalTime();
    }

    public int Pid { get; }
    public int ParentPid { get; set; }
    public string ProcessName { get; set; }
    public string ImagePath { get; set; }
    public string CommandLine { get; set; }
    public DateTime StartedUtc { get; }
    public DateTime? EndedUtc { get; set; }
}
