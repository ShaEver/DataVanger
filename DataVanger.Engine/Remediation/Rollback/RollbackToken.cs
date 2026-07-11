using System;

namespace DataVanger.Engine.Remediation.Rollback;

/// <summary>
/// The kind of rollback a reversible action supports. <see cref="None"/> means
/// the action is irreversible and MUST be explicitly classified as such — it is
/// never a silent default for a reversible action.
/// </summary>
public enum RollbackTokenKind
{
    /// <summary>Irreversible: no rollback is possible. Must be paired with
    /// <c>IsReversible == false</c> on the descriptor.</summary>
    None = 0,

    /// <summary>Restore the quarantined original from the secure store.</summary>
    QuarantineRestore,

    /// <summary>Re-create a backed-up registry value.</summary>
    RegistryValueBackup,

    /// <summary>Re-import an exported scheduled-task definition.</summary>
    ScheduledTaskExport,

    /// <summary>Restore a service's prior start type / state.</summary>
    ServiceConfigBackup,

    /// <summary>Restore a startup-folder entry from quarantine.</summary>
    StartupEntryBackup,

    /// <summary>Restore a setting from a captured snapshot (hosts/IFEO/proxy…).</summary>
    SettingsSnapshot,
}

/// <summary>
/// An opaque, action-specific rollback token. The <see cref="Payload"/> is a
/// deliberately opaque string whose meaning is private to the action that
/// produced it (e.g. a quarantine id, a serialized registry value). The base
/// contract is typed (a <see cref="RollbackTokenKind"/>) so callers cannot pass
/// a raw stringly blob with no classification.
///
/// Use <see cref="Irreversible"/> to represent the explicit "no rollback"
/// classification; use <see cref="For"/> for a real reversible token.
/// </summary>
public sealed record RollbackToken
{
    private RollbackToken(RollbackTokenKind kind, string? payload, RemediationCorrelationId correlationId)
    {
        Kind = kind;
        Payload = payload;
        CorrelationId = correlationId;
    }

    public RollbackTokenKind Kind { get; }

    /// <summary>Opaque, action-private recovery data. Null only for
    /// <see cref="RollbackTokenKind.None"/>.</summary>
    public string? Payload { get; }

    public RemediationCorrelationId CorrelationId { get; }

    /// <summary>True when this token can actually undo the action.</summary>
    public bool CanRollback => Kind != RollbackTokenKind.None && !string.IsNullOrEmpty(Payload);

    /// <summary>The explicit "this action cannot be undone" classification.</summary>
    public static RollbackToken Irreversible(RemediationCorrelationId correlationId)
        => new(RollbackTokenKind.None, null, correlationId);

    /// <summary>A real rollback token. <paramref name="kind"/> must not be
    /// <see cref="RollbackTokenKind.None"/> and <paramref name="payload"/> must
    /// be non-empty — otherwise the call is a programming error.</summary>
    public static RollbackToken For(RollbackTokenKind kind, string payload, RemediationCorrelationId correlationId)
    {
        if (kind == RollbackTokenKind.None)
            throw new ArgumentException("A reversible rollback token cannot have kind None.", nameof(kind));
        if (string.IsNullOrWhiteSpace(payload))
            throw new ArgumentException("A reversible rollback token requires a non-empty payload.", nameof(payload));
        return new RollbackToken(kind, payload, correlationId);
    }
}
