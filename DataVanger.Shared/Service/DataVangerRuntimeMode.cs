namespace DataVanger.Shared.Service;

/// <summary>
/// Execution mode for the DataVanger service runtime.
///
/// Development is the safe default. Service mode is only entered when the
/// host is launched explicitly with the corresponding command-line flag —
/// it must never be triggered by tests or by `dotnet build`.
/// </summary>
public enum DataVangerRuntimeMode
{
    /// <summary>
    /// Default, fully development-safe behavior. No resident loop, no
    /// installation, no privileged operations. Used by tests and by the
    /// developer workflow.
    /// </summary>
    Development = 0,

    /// <summary>
    /// Explicit interactive console execution. The runtime starts and is
    /// kept alive until a cancellation/shutdown signal is received. Still
    /// non-aggressive and safe to terminate.
    /// </summary>
    Console = 1,

    /// <summary>
    /// Reserved for a future real Windows Service host. In this phase the
    /// service mode is recognized for diagnostic reporting only and never
    /// performs any installation, registration, or privileged action.
    /// </summary>
    Service = 2,
}
