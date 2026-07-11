namespace DataVanger.Shared.Behavioral.Runtime;

/// <summary>
/// The kind of normalized behavioral observation produced by the
/// <c>BehavioralRuntimeEventAdapter</c> from a
/// <see cref="DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent"/>.
///
/// Observations are descriptive, normalized inputs to the conservative
/// runtime rule evaluator. They are NOT verdicts.
/// </summary>
public enum BehavioralObservationKind
{
    Unknown = 0,

    /// <summary>A process was created (lineage / image-path context).</summary>
    ProcessStart,

    /// <summary>A command line was observed for a process.</summary>
    CommandLine,

    /// <summary>A script-interpreter indicator was observed (PowerShell, etc.).</summary>
    Script,

    /// <summary>File activity surfaced by real-time protection / ETW.</summary>
    FileActivity,

    /// <summary>
    /// A persistence-related event (Run key, startup folder, scheduled
    /// task, service, WMI subscription) — only when the pipeline already
    /// produces such events.
    /// </summary>
    Persistence,

    /// <summary>
    /// A security-tamper event (disabling defenses, stopping security
    /// services, clearing logs) — only when the pipeline already produces
    /// such events.
    /// </summary>
    Tamper,
}
