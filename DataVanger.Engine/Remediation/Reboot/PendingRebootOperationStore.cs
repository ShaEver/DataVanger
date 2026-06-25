using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.Engine.Remediation.Reboot;

/// <summary>One append-only state-transition record for a pending operation.</summary>
public sealed record PendingOperationJournalRecord(
    PendingOperationId Id,
    PendingOperationStatus Status,
    DateTimeOffset TimestampUtc,
    string Detail);

/// <summary>
/// Durable journal + current-state projection of pending reboot operations. The
/// projection is derived from an append-only log of state transitions, so a
/// replay/cancel that re-applies the same transition is a no-op (idempotency).
///
/// Status transitions are validated: a Queued op may be Canceled, Replayed, or
/// Failed; a Replayed op may be Verified or Failed; terminal states
/// (Canceled/Verified) and an already-applied transition do not change state.
/// </summary>
public interface IPendingRebootOperationStore
{
    void Add(PendingRebootOperation operation);
    PendingRebootOperation? Get(PendingOperationId id);
    IReadOnlyList<PendingRebootOperation> List();
    IReadOnlyList<PendingOperationJournalRecord> Journal();

    /// <summary>
    /// Attempts a status transition. Returns true if it changed state, false if it
    /// was a no-op (already in that status, or an invalid/forbidden transition).
    /// Idempotent by construction: re-applying the same transition is a harmless
    /// false.
    /// </summary>
    bool TryTransition(PendingOperationId id, PendingOperationStatus to, string detail, DateTimeOffset nowUtc);
}

/// <summary>In-memory implementation. The ONLY store in this phase (durable
/// persistence is a later concern); never writes to the real registry.</summary>
public sealed class InMemoryPendingRebootOperationStore : IPendingRebootOperationStore
{
    private readonly object _gate = new();
    private readonly Dictionary<PendingOperationId, PendingRebootOperation> _projection = new();
    private readonly List<PendingOperationJournalRecord> _journal = new();

    public void Add(PendingRebootOperation operation)
    {
        if (operation is null) throw new ArgumentNullException(nameof(operation));
        lock (_gate)
        {
            if (_projection.ContainsKey(operation.Id))
                throw new InvalidOperationException($"Pending operation {operation.Id} already exists.");
            _projection[operation.Id] = operation;
            _journal.Add(new PendingOperationJournalRecord(operation.Id, operation.Status, operation.CreatedUtc, "Queued"));
        }
    }

    public PendingRebootOperation? Get(PendingOperationId id)
    {
        lock (_gate) { return _projection.TryGetValue(id, out var op) ? op : null; }
    }

    public IReadOnlyList<PendingRebootOperation> List()
    {
        lock (_gate) { return _projection.Values.ToArray(); }
    }

    public IReadOnlyList<PendingOperationJournalRecord> Journal()
    {
        lock (_gate) { return _journal.ToArray(); }
    }

    public bool TryTransition(PendingOperationId id, PendingOperationStatus to, string detail, DateTimeOffset nowUtc)
    {
        lock (_gate)
        {
            if (!_projection.TryGetValue(id, out var op)) return false;
            if (op.Status == to) return false;              // idempotent no-op
            if (!IsAllowed(op.Status, to)) return false;    // forbidden transition

            _projection[id] = op with { Status = to, LastUpdatedUtc = nowUtc };
            _journal.Add(new PendingOperationJournalRecord(id, to, nowUtc, detail));
            return true;
        }
    }

    private static bool IsAllowed(PendingOperationStatus from, PendingOperationStatus to) => from switch
    {
        PendingOperationStatus.Queued => to is PendingOperationStatus.Canceled
            or PendingOperationStatus.Replayed or PendingOperationStatus.Failed,
        PendingOperationStatus.Replayed => to is PendingOperationStatus.Verified
            or PendingOperationStatus.Failed,
        _ => false, // Canceled / Verified / Failed are terminal
    };
}
