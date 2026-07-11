namespace DataVanger.Memory;

/// <summary>
/// Explains why a memory scan returned no/partial findings. Lets
/// callers report graceful degradation rather than treating it as
/// failure.
/// </summary>
public enum MemoryScanDegradationReason
{
    /// <summary>Scan completed normally.</summary>
    None = 0,

    /// <summary>Memory scanning is not supported on this platform/host.</summary>
    PlatformUnsupported,

    /// <summary>Memory scanning is disabled by configuration.</summary>
    DisabledByConfiguration,

    /// <summary>The scanner could not open enough processes to give useful coverage.</summary>
    InsufficientPrivileges,

    /// <summary>Cancellation was requested before the scan finished.</summary>
    Cancelled,

    /// <summary>Per-scan overall timeout elapsed.</summary>
    Timeout,

    /// <summary>Per-process or per-region limits were exceeded; scan was throttled.</summary>
    LimitsExceeded,
}
