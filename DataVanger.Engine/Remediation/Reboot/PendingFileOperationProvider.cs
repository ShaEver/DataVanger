using System;
using System.Collections.Generic;

namespace DataVanger.Engine.Remediation.Reboot;

/// <summary>Detects whether a file is locked (in use such that it cannot be
/// deleted now). The real implementation would attempt an exclusive/delete-share
/// open; in this phase only a fake exists.</summary>
public interface ILockedFileDetector
{
    bool IsLocked(string path);
}

/// <summary>
/// OS seam for queuing a delete to occur on the next reboot (the real
/// implementation would use <c>MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)</c> /
/// <c>PendingFileRenameOperations</c>). In this phase ONLY a fake exists; no real
/// registry write or reboot scheduling happens anywhere.
/// </summary>
public interface IPendingFileOperationProvider
{
    void QueueDeleteOnReboot(string path);
    void CancelQueuedDelete(string path);
    bool IsQueued(string path);
}

/// <summary>
/// Test/simulation pending-file-operation provider. Records queued/canceled paths
/// in memory and NEVER touches the registry or schedules a reboot. The name and
/// the fact that it is the only implementation make accidental production use
/// obvious.
/// </summary>
public sealed class SimulationPendingFileOperationProvider : IPendingFileOperationProvider
{
    private readonly HashSet<string> _queued = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyCollection<string> Queued
    {
        get { lock (_queued) { return new List<string>(_queued); } }
    }

    public void QueueDeleteOnReboot(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Path required.", nameof(path));
        lock (_queued) { _queued.Add(path); }
    }

    public void CancelQueuedDelete(string path)
    {
        lock (_queued) { _queued.Remove(path); }
    }

    public bool IsQueued(string path)
    {
        lock (_queued) { return _queued.Contains(path); }
    }
}
