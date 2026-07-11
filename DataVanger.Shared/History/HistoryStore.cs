using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace DataVanger.Shared.History;

/// <summary>
/// Append-only, bounded, JSON-backed persistent history of scans, detections,
/// remediation actions, verification, rollback, updates, and service events.
///
/// Honesty contract (Phase 07): the store never reports a remediation as resolved
/// on the strength of a RemediationAction alone — even a "Succeeded" action stays
/// unresolved until a passing <see cref="HistoryEventKind.Verification"/> event for
/// the same correlation arrives. A pure in-memory instance is used for tests; a
/// path-backed instance persists durably and tolerates a corrupt file by starting
/// empty rather than throwing to callers.
/// </summary>
public sealed class HistoryStore
{
    /// <summary>Upper bound on retained records; oldest are trimmed first.</summary>
    public const int MaxEntries = 5000;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly object _sync = new();
    private readonly List<HistoryEvent> _events = new();
    private readonly string? _path;

    /// <summary>In-memory only (no persistence).</summary>
    public HistoryStore() { }

    /// <summary>Path-backed; loads any existing history on construction.</summary>
    public HistoryStore(string path)
    {
        _path = path ?? throw new ArgumentNullException(nameof(path));
        Load();
    }

    public void Append(HistoryEvent historyEvent)
    {
        if (historyEvent is null) throw new ArgumentNullException(nameof(historyEvent));
        lock (_sync)
        {
            _events.Add(historyEvent);
            if (_events.Count > MaxEntries)
                _events.RemoveRange(0, _events.Count - MaxEntries);
            Persist();
        }
    }

    public IReadOnlyList<HistoryEvent> All()
    {
        lock (_sync) return _events.ToArray();
    }

    public IReadOnlyList<HistoryEvent> ForCorrelation(string correlationId)
    {
        lock (_sync) return _events.Where(e => e.CorrelationId == correlationId).ToArray();
    }

    public int Count
    {
        get { lock (_sync) return _events.Count; }
    }

    /// <summary>
    /// True only when a remediation for <paramref name="correlationId"/> has been
    /// confirmed by a passing verification event. A RemediationAction by itself
    /// (including a "Succeeded" one, or a reboot-required one) is NOT verified.
    /// </summary>
    public bool IsRemediationVerified(string correlationId)
    {
        if (string.IsNullOrEmpty(correlationId)) return false;
        lock (_sync)
        {
            bool hasRemediation = _events.Any(e =>
                e.CorrelationId == correlationId && e.Kind == HistoryEventKind.RemediationAction);
            bool hasPassingVerification = _events.Any(e =>
                e.CorrelationId == correlationId &&
                e.Kind == HistoryEventKind.Verification &&
                e.Outcome == HistoryOutcome.Verified);
            return hasRemediation && hasPassingVerification;
        }
    }

    private void Load()
    {
        if (_path is null || !File.Exists(_path)) return;
        try
        {
            var json = File.ReadAllText(_path);
            var loaded = JsonSerializer.Deserialize<List<HistoryEvent>>(json);
            if (loaded is not null)
            {
                _events.Clear();
                _events.AddRange(loaded);
            }
        }
        catch (JsonException)
        {
            // Corrupt history file — start empty rather than throwing to the caller.
        }
        catch (IOException)
        {
            // History temporarily unreadable — degrade to empty, observable on next save.
        }
    }

    private void Persist()
    {
        if (_path is null) return;
        try
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(_path, JsonSerializer.Serialize(_events, JsonOptions));
        }
        catch (IOException)
        {
            // History persistence is best-effort; a write failure must not abort the caller.
        }
        catch (UnauthorizedAccessException)
        {
            // No permission to persist history; keep the in-memory record.
        }
    }
}
