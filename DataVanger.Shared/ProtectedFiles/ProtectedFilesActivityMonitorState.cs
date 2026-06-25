namespace DataVanger.Shared.ProtectedFiles;

/// <summary>
/// Lifecycle / health state of the Protected Files Activity Monitor
/// (Phase 2 / Step 07). Mirrors the conservative state vocabulary used
/// elsewhere in the runtime stack so the value can later be surfaced in
/// status/health UI.
/// </summary>
public enum ProtectedFilesActivityMonitorState
{
    /// <summary>Monitor is turned off; subscribes to nothing and emits no evidence.</summary>
    Disabled = 0,

    Starting,

    /// <summary>Running and actively translating file telemetry into evidence.</summary>
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
