namespace DataVanger.Runtime.Etw;

/// <summary>
/// Marker interface for ETW-backed telemetry providers.
///
/// Concrete implementations live in OS-specific builds; this build ships
/// a safe no-op (<see cref="NullEtwProvider"/>) and a test-only in-memory
/// replay provider (<see cref="InMemoryEtwProvider"/>). The factory
/// (<see cref="EtwProviderFactory"/>) chooses the right one based on
/// runtime feature detection.
/// </summary>
public interface IEtwTelemetryProvider : IRuntimeTelemetryProvider
{
    /// <summary>True when the running OS/process actually has access to ETW.</summary>
    bool IsHostSupported { get; }
}
