namespace DataVanger.SelfProtection;

/// <summary>
/// Lifecycle state of <see cref="SelfProtectionManager"/>.
///
/// Mirrors the "fail closed" contract used by the Runtime telemetry
/// subsystem (see <see cref="DataVanger.Runtime.RuntimeProviderState"/>):
/// the manager never throws on Start; instead it transitions into a
/// terminal state that callers can inspect.
/// </summary>
public enum SelfProtectionState
{
    /// <summary>Not yet started.</summary>
    NotStarted = 0,

    /// <summary>Level is <see cref="SelfProtectionLevel.Off"/>; manager is a no-op.</summary>
    Disabled,

    /// <summary>Running in development mode — no destructive actions.</summary>
    DevelopmentMode,

    /// <summary>Running normally and emitting tamper evidence.</summary>
    Active,

    /// <summary>Running but at least one component reported a degraded backend.</summary>
    Degraded,

    /// <summary>Stop() / Dispose() was called.</summary>
    Stopped,
}
