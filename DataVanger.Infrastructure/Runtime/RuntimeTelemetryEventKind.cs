namespace DataVanger.Runtime;

/// <summary>
/// Taxonomy of runtime telemetry event kinds emitted by ETW/AMSI
/// providers. Mirrors the spirit of <see cref="DataVanger.Behavioral.BehavioralEventKind"/>
/// but stays decoupled — providers describe what they observed, the
/// bridge decides which behavioral kind (if any) it maps to.
/// </summary>
public enum RuntimeTelemetryEventKind
{
    /// <summary>Sentinel.</summary>
    None = 0,

    ProcessStart,
    ProcessEnd,
    ImageLoad,
    ScriptExecution,
    AmsiScan,
    AmsiBypassIndicator,
    SecurityRelevant,
}
