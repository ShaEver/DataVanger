namespace DataVanger.Shared.RuntimeEvents;

/// <summary>
/// Category used for routing, reporting, and (future) UI filtering of
/// runtime security events. Categories MUST NOT be interpreted as
/// classification verdicts — a <see cref="RansomwareSuspicion"/>
/// category event alone is NOT ConfirmedMalware.
/// </summary>
public enum RuntimeEventCategory
{
    Unknown = 0,
    FileCreated,
    FileChanged,
    FileDeleted,
    FileRenamed,
    FileScanRequested,
    FileScanCompleted,
    ProcessCreated,
    ProcessTerminated,
    CommandLineObserved,
    ScriptObserved,
    /// <summary>
    /// Process-memory injection/tamper indicator. This is heuristic telemetry,
    /// never a malware verdict and never authorization for remediation.
    /// </summary>
    InjectionObserved,
    PersistenceObserved,
    TamperObserved,
    RansomwareSuspicion,
    QuarantineAction,
    UpdateAction,
    ServiceLifecycle,
    HealthStatus,
    DetectionEvidence,
    PolicyDecision,
    ConfigurationChange,
    Error,
    Warning,
}
