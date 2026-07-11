namespace DataVanger.Shared.Etw;

/// <summary>
/// Lifecycle / availability status of an ETW runtime provider introduced
/// in Phase 2 Step 05 (ETW Real Provider).
///
/// Anti-FP guarantee:
///   Status is operational telemetry only. None of these values
///   classifies a process or file as ConfirmedMalware. A
///   <see cref="Degraded"/> or <see cref="Faulted"/> provider must NEVER
///   be treated as a malware verdict — it indicates the collection
///   surface, not the threat surface.
/// </summary>
public enum EtwProviderStatus
{
    /// <summary>Provider has not been started or is intentionally off in configuration.</summary>
    Disabled = 0,

    /// <summary>Running OS does not support ETW (e.g. non-Windows host).</summary>
    UnsupportedPlatform,

    /// <summary>Configuration explicitly forbids the real provider (development/test).</summary>
    NotConfigured,

    /// <summary>Provider is starting up; not yet emitting events.</summary>
    Starting,

    /// <summary>Provider is running and may emit normalized events.</summary>
    Running,

    /// <summary>Provider is running but with reduced functionality (some sub-collectors failed).</summary>
    Degraded,

    /// <summary>Provider could not start because the host lacked required privileges.</summary>
    PermissionDenied,

    /// <summary>Provider could not start because a required ETW session/provider is unavailable.</summary>
    ProviderUnavailable,

    /// <summary>Provider faulted after starting; events are no longer being collected.</summary>
    Faulted,

    /// <summary>Provider was started and then cleanly stopped/disposed.</summary>
    Stopped,
}
