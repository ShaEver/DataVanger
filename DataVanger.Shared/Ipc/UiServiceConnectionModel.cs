namespace DataVanger.Shared.Ipc;

/// <summary>
/// Pure, WPF-independent UI-facing model that translates a
/// <see cref="ServiceConnectionStatus"/> into honest display text and control
/// gating. Lives in Shared so it is fully unit-testable without a UI host.
///
/// Anti-security-theater rule (enforced here):
///   - Service-owned runtime controls are enabled ONLY when the service is
///     genuinely reachable (Connected / DevelopmentHost / TestHost).
///   - Service-owned runtime protection is reported active ONLY when the
///     service is connected AND honestly reports active protection.
///
/// This model never gates the existing in-process manual scanner — that
/// remains available regardless of service state.
/// </summary>
public sealed class UiServiceConnectionModel
{
    public UiServiceConnectionModel(
        ServiceConnectionStatus status = ServiceConnectionStatus.Unknown,
        bool serviceReportsActiveProtection = false)
    {
        Status = status;
        ServiceReportsActiveProtection = serviceReportsActiveProtection;
    }

    public ServiceConnectionStatus Status { get; }

    /// <summary>
    /// Whether the service itself honestly reports active protection. Only
    /// meaningful when <see cref="IsConnected"/> is true.
    /// </summary>
    public bool ServiceReportsActiveProtection { get; }

    /// <summary>True when connected to a real / development / test host.</summary>
    public bool IsConnected =>
        Status is ServiceConnectionStatus.Connected
            or ServiceConnectionStatus.DevelopmentHost
            or ServiceConnectionStatus.TestHost;

    /// <summary>
    /// True when the service is unreachable, not installed, or not running.
    /// Degraded counts as available-but-impaired, not unavailable.
    /// </summary>
    public bool IsUnavailable =>
        Status is ServiceConnectionStatus.NotInstalled
            or ServiceConnectionStatus.NotRunning
            or ServiceConnectionStatus.Unreachable
            or ServiceConnectionStatus.Unknown;

    /// <summary>
    /// Whether service-owned runtime-only controls should be enabled. False
    /// whenever the service is unavailable so the UI cannot drive a runtime it
    /// is not actually connected to.
    /// </summary>
    public bool AreServiceRuntimeControlsEnabled => IsConnected;

    /// <summary>
    /// Whether the UI may present service-owned runtime protection as active.
    /// Requires a live connection AND an honest active-protection report.
    /// </summary>
    public bool ShowServiceProtectionAsActive => IsConnected && ServiceReportsActiveProtection;

    /// <summary>Short, honest status label for the UI (e.g. "Service: Connected").</summary>
    public string StatusText => Status switch
    {
        ServiceConnectionStatus.Connected => "Service: Connected",
        ServiceConnectionStatus.NotInstalled => "Service: Not installed",
        ServiceConnectionStatus.NotRunning => "Service: Not running",
        ServiceConnectionStatus.Unreachable => "Service: Unreachable",
        ServiceConnectionStatus.DevelopmentHost => "Service: Development host",
        ServiceConnectionStatus.TestHost => "Service: Test host",
        ServiceConnectionStatus.Degraded => "Service: Degraded",
        _ => "Service: Unknown",
    };

    /// <summary>Longer, honest detail for a tooltip.</summary>
    public string StatusDetail => Status switch
    {
        ServiceConnectionStatus.Connected =>
            "Connected to the resident DataVanger service. Runtime protection state is authoritative from the service.",
        ServiceConnectionStatus.NotInstalled =>
            "No resident DataVanger service is installed. Manual scanning remains available; runtime service controls are disabled.",
        ServiceConnectionStatus.NotRunning =>
            "The resident DataVanger service is not running. Manual scanning remains available; runtime service controls are disabled.",
        ServiceConnectionStatus.Unreachable =>
            "The resident DataVanger service could not be reached. Manual scanning remains available; runtime service controls are disabled.",
        ServiceConnectionStatus.DevelopmentHost =>
            "Connected to an in-process development host (not a real installed service).",
        ServiceConnectionStatus.TestHost =>
            "Connected to an in-memory test host.",
        ServiceConnectionStatus.Degraded =>
            "The service is reachable but reports a degraded runtime state.",
        _ => "Service connection state is unknown.",
    };
}
