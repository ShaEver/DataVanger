namespace DataVanger.Shared.Behavioral.Runtime;

/// <summary>
/// Lifecycle / health state of the Behavioral Engine Runtime Binding.
/// Mirrors the conservative state vocabulary used elsewhere in the
/// runtime stack so the value can later be surfaced in status/health UI.
/// </summary>
public enum BehavioralRuntimeBindingState
{
    /// <summary>Binding is turned off; it subscribes to nothing and emits no evidence.</summary>
    Disabled = 0,

    Starting,

    /// <summary>Running and actively translating telemetry into evidence.</summary>
    Running,

    /// <summary>Running in passive (observe/report only) mode — never acts.</summary>
    Passive,

    /// <summary>Running in development-safe mode — never acts.</summary>
    DevelopmentSafe,

    /// <summary>Running but state/rate limits were reached; some events were dropped.</summary>
    Degraded,

    Stopping,

    Stopped,

    Failed,
}
