using System;
using System.Collections.Generic;
using DataVanger.Shared.Ipc;

namespace DataVanger.Service.Ipc;

/// <summary>
/// Deterministic, in-memory registry of scan operations started through IPC.
/// This phase does NOT execute or rewrite the scan engine — it only tracks
/// bounded operation ids and their state so the UI can poll status and cancel.
/// Thread-safe; no background loops.
/// </summary>
public sealed class ScanOperationRegistry
{
    private readonly object _gate = new();
    private readonly Dictionary<string, ScanStatusDto> _operations = new(StringComparer.Ordinal);

    /// <summary>Registers a new queued scan operation and returns its id.</summary>
    public string Start(ScanRequestKind kind)
    {
        string operationId = "scan-" + Guid.NewGuid().ToString("N");
        var status = new ScanStatusDto
        {
            OperationId = operationId,
            State = "Queued",
            Kind = kind.ToString(),
            Message = "Scan request accepted and queued.",
        };

        lock (_gate)
        {
            _operations[operationId] = status;
        }

        return operationId;
    }

    /// <summary>Returns the status for an operation, or null when unknown.</summary>
    public ScanStatusDto? Get(string operationId)
    {
        if (string.IsNullOrWhiteSpace(operationId)) return null;
        lock (_gate)
        {
            return _operations.TryGetValue(operationId, out var status) ? status : null;
        }
    }

    /// <summary>Marks an operation cancelled. Returns false when unknown.</summary>
    public bool Cancel(string operationId)
    {
        if (string.IsNullOrWhiteSpace(operationId)) return false;
        lock (_gate)
        {
            if (!_operations.TryGetValue(operationId, out var status)) return false;
            _operations[operationId] = new ScanStatusDto
            {
                OperationId = status.OperationId,
                State = "Cancelled",
                Kind = status.Kind,
                Message = "Scan operation cancelled by user.",
            };
            return true;
        }
    }
}

/// <summary>
/// Tracks the user's realtime-protection pause/resume intent. Honest: this is
/// intent only — it never claims active protection and never starts a loop.
/// </summary>
public sealed class ProtectionControlState
{
    private readonly object _gate = new();
    private bool _pauseRequested;

    public bool PauseRequested
    {
        get { lock (_gate) return _pauseRequested; }
    }

    public void RequestPause()
    {
        lock (_gate) _pauseRequested = true;
    }

    public void RequestResume()
    {
        lock (_gate) _pauseRequested = false;
    }
}
