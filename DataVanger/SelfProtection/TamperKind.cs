namespace DataVanger.SelfProtection;

/// <summary>
/// Taxonomy of tamper-attempt signals produced by the Self-Protection
/// subsystem.
///
/// Kinds describe what was observed, NOT how risky it is. Severity is a
/// separate dimension (<see cref="TamperSeverity"/>) so the same kind can
/// be reported with different severities depending on context.
/// </summary>
public enum TamperKind
{
    /// <summary>Sentinel — not a real event.</summary>
    None = 0,

    /// <summary>A protected configuration file changed unexpectedly.</summary>
    ConfigurationModified,

    /// <summary>A protected configuration file is missing.</summary>
    ConfigurationMissing,

    /// <summary>The hash of a protected runtime binary differs from baseline.</summary>
    BinaryIntegrityFailure,

    /// <summary>A protected signature/YARA/reputation database changed.</summary>
    SignatureDatabaseTampering,

    /// <summary>Quarantine storage or metadata changed unexpectedly.</summary>
    QuarantineTampering,

    /// <summary>A monitored runtime component reported an unexpected stop.</summary>
    ServiceStopAttempt,

    /// <summary>Runtime telemetry (ETW/AMSI) stopped emitting events.</summary>
    TelemetryInterruption,

    /// <summary>Watchdog observed repeated failures and gave up.</summary>
    WatchdogGaveUp,

    /// <summary>A recovery action ran. Recorded for forensic explainability.</summary>
    RecoveryActionTaken,
}
