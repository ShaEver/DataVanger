using System;

namespace DataVanger.SelfProtection;

/// <summary>
/// Outcome of a single watchdog observation pass on one component.
///
/// Watchdog observations are deliberately minimal: the watchdog only
/// records that a component was observed alive/dead; it does NOT decide
/// what recovery means — that belongs to the
/// <see cref="RecoveryManager"/>.
/// </summary>
public sealed class WatchdogObservation
{
    public WatchdogObservation(
        string component,
        WatchdogOutcome outcome,
        int attemptCount,
        DateTime timestampUtc,
        string description)
    {
        Component = component ?? "";
        Outcome = outcome;
        AttemptCount = attemptCount;
        TimestampUtc = timestampUtc == default ? DateTime.UtcNow : timestampUtc.ToUniversalTime();
        Description = description ?? "";
    }

    public string Component { get; }
    public WatchdogOutcome Outcome { get; }
    public int AttemptCount { get; }
    public DateTime TimestampUtc { get; }
    public string Description { get; }

    public override string ToString()
        => $"[{TimestampUtc:HH:mm:ss}] watchdog/{Component} {Outcome} attempt={AttemptCount}: {Description}";
}

public enum WatchdogOutcome
{
    /// <summary>Component reported healthy.</summary>
    Healthy = 0,

    /// <summary>Component reported unhealthy and recovery was attempted.</summary>
    RecoveryAttempted,

    /// <summary>Cooldown was active — no action taken this tick.</summary>
    OnCooldown,

    /// <summary>Component exceeded the retry budget; watchdog gave up.</summary>
    GaveUp,

    /// <summary>Recovery callback threw and the watchdog swallowed it.</summary>
    RecoveryFailed,
}
