using System;

namespace DataVanger.SelfProtection;

/// <summary>
/// Recorded recovery action.
///
/// The recovery system is informational: it logs what was done so the
/// reporting layer can explain "what recovered, what failed" to the
/// user, as required by 09_SELF_PROTECTION.md.
///
/// Actions NEVER carry malware verdicts. They never escalate evidence
/// strength past <see cref="DataVanger.Core.EvidenceStrength.High"/>.
/// </summary>
public sealed class RecoveryAction
{
    public RecoveryAction(
        string component,
        RecoveryOutcome outcome,
        string description,
        DateTime timestampUtc)
    {
        Component = component ?? "";
        Outcome = outcome;
        Description = description ?? "";
        TimestampUtc = timestampUtc == default ? DateTime.UtcNow : timestampUtc.ToUniversalTime();
    }

    public string Component { get; }
    public RecoveryOutcome Outcome { get; }
    public string Description { get; }
    public DateTime TimestampUtc { get; }

    public override string ToString()
        => $"[{TimestampUtc:HH:mm:ss}] recovery/{Component} {Outcome}: {Description}";
}

public enum RecoveryOutcome
{
    Succeeded = 0,
    Failed,
    Skipped,
}
