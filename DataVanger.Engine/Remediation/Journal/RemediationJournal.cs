using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.Engine.Remediation.Journal;

/// <summary>Whether a journal record captures the INTENT to act (written before
/// any effect) or the OUTCOME of an action (written after).</summary>
public enum RemediationJournalEntryKind
{
    Intent = 0,
    Outcome,
}

/// <summary>
/// One append-only journal record. The Intent record is written BEFORE an action
/// is attempted and captures what is about to happen and a reference to the
/// before-state; the Outcome record is written AFTER and captures the result and
/// any rollback token. Records are immutable.
/// </summary>
public sealed record RemediationJournalRecord
{
    public required RemediationCorrelationId CorrelationId { get; init; }
    public required int StepOrder { get; init; }
    public required RemediationJournalEntryKind EntryKind { get; init; }
    public required RemediationActionKind ActionKind { get; init; }
    public required string TargetMatchKey { get; init; }
    public required DateTimeOffset TimestampUtc { get; init; }

    /// <summary>Opaque reference to the captured before-state (e.g. a quarantine
    /// id or snapshot id). Present on Intent records for reversible actions.</summary>
    public string? BeforeStateRef { get; init; }

    /// <summary>The rollback classification recorded for this action.</summary>
    public Rollback.RollbackTokenKind RollbackKind { get; init; }

    /// <summary>Outcome text (Outcome records only).</summary>
    public string? Outcome { get; init; }
}

/// <summary>Append-only writer. Implementations must never mutate or delete an
/// existing record.</summary>
public interface IRemediationJournalWriter
{
    void Append(RemediationJournalRecord record);
}

/// <summary>Read side of the journal, for audit and rollback lookups.</summary>
public interface IRemediationJournal : IRemediationJournalWriter
{
    IReadOnlyList<RemediationJournalRecord> All();
    IReadOnlyList<RemediationJournalRecord> ForCorrelation(RemediationCorrelationId correlationId);

    /// <summary>True if an Intent record already exists for the given step — the
    /// invariant the executor relies on to guarantee journal-before-action.</summary>
    bool HasIntent(RemediationCorrelationId correlationId, int stepOrder);
}

/// <summary>
/// In-memory append-only journal. The ONLY journal implementation in phase 03A;
/// a durable store is a later phase. Thread-safe; never mutates an appended
/// record.
/// </summary>
public sealed class InMemoryRemediationJournal : IRemediationJournal
{
    private readonly object _gate = new();
    private readonly List<RemediationJournalRecord> _records = new();

    public void Append(RemediationJournalRecord record)
    {
        if (record is null) throw new ArgumentNullException(nameof(record));
        lock (_gate)
        {
            _records.Add(record);
        }
    }

    public IReadOnlyList<RemediationJournalRecord> All()
    {
        lock (_gate)
        {
            return _records.ToArray();
        }
    }

    public IReadOnlyList<RemediationJournalRecord> ForCorrelation(RemediationCorrelationId correlationId)
    {
        lock (_gate)
        {
            return _records.Where(r => r.CorrelationId.Equals(correlationId)).ToArray();
        }
    }

    public bool HasIntent(RemediationCorrelationId correlationId, int stepOrder)
    {
        lock (_gate)
        {
            return _records.Any(r =>
                r.CorrelationId.Equals(correlationId)
                && r.StepOrder == stepOrder
                && r.EntryKind == RemediationJournalEntryKind.Intent);
        }
    }
}
