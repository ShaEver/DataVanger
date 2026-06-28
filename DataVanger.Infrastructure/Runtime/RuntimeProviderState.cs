namespace DataVanger.Runtime;

/// <summary>
/// Lifecycle state of a runtime provider.
///
/// Providers must "fail closed" — a provider that cannot start (no
/// privileges, missing OS feature, environment unsupported) reports
/// <see cref="Unavailable"/> and stays a no-op. The application keeps
/// working without runtime telemetry, just like it does today.
/// </summary>
public enum RuntimeProviderState
{
    /// <summary>Provider has not been started yet.</summary>
    NotStarted = 0,

    /// <summary>Provider is running and emitting events.</summary>
    Running,

    /// <summary>Provider was started but is intentionally a no-op (mock/test).</summary>
    RunningMock,

    /// <summary>Start was attempted but the host environment does not support the provider.</summary>
    Unavailable,

    /// <summary>Start was attempted and failed (insufficient privileges, missing DLL, etc).</summary>
    Failed,

    /// <summary>Provider was started and then stopped/disposed.</summary>
    Stopped,
}
