using System;

namespace DataVanger.SelfProtection;

/// <summary>
/// Immutable tamper-attempt event.
///
/// Carries the minimum information needed by the reporting layer to
/// explain a self-protection observation:
///
///   - <see cref="Kind"/>         : what was observed
///   - <see cref="Severity"/>     : how serious the subsystem rates it
///   - <see cref="Component"/>    : logical component name (e.g. "config", "quarantine")
///   - <see cref="TargetPath"/>   : file/key/path being protected (best-effort)
///   - <see cref="Description"/>  : human-readable explanation
///   - <see cref="TimestampUtc"/> : when the observation happened
///
/// The event NEVER carries a malware verdict. Downstream rules and the
/// classifier remain the only path to confirmed malware classification.
/// </summary>
public sealed class TamperEvent
{
    public TamperEvent(
        TamperKind kind,
        TamperSeverity severity,
        string component,
        string targetPath,
        string description,
        DateTime timestampUtc)
    {
        Kind = kind;
        Severity = severity;
        Component = component ?? "";
        TargetPath = targetPath ?? "";
        Description = description ?? "";
        TimestampUtc = timestampUtc == default ? DateTime.UtcNow : timestampUtc.ToUniversalTime();
    }

    public TamperKind Kind { get; }
    public TamperSeverity Severity { get; }
    public string Component { get; }
    public string TargetPath { get; }
    public string Description { get; }
    public DateTime TimestampUtc { get; }

    public override string ToString()
        => $"[{TimestampUtc:HH:mm:ss.fff}] {Kind} ({Severity}) component={Component} :: {Description}";
}
