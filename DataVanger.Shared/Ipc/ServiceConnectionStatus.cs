namespace DataVanger.Shared.Ipc;

/// <summary>
/// Honest connection state between the UI and the resident service. The UI
/// surfaces this directly. Anti-security-theater rule: when the service is
/// not <see cref="Connected"/>, the UI MUST NOT present service-owned runtime
/// protection as active.
/// </summary>
public enum ServiceConnectionStatus
{
    /// <summary>State has not been determined yet.</summary>
    Unknown = 0,

    /// <summary>Connected to a real, running service host.</summary>
    Connected = 1,

    /// <summary>No service is installed on the machine.</summary>
    NotInstalled = 2,

    /// <summary>The service is installed but not currently running.</summary>
    NotRunning = 3,

    /// <summary>The service could not be reached (transport failure / timeout).</summary>
    Unreachable = 4,

    /// <summary>Connected to an in-process development host (not a real service).</summary>
    DevelopmentHost = 5,

    /// <summary>Connected to an in-memory test host.</summary>
    TestHost = 6,

    /// <summary>Reachable, but the service reports a degraded runtime state.</summary>
    Degraded = 7,
}
