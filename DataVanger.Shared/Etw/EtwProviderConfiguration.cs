using System;

namespace DataVanger.Shared.Etw;

/// <summary>
/// Configuration for the ETW runtime provider introduced in Phase 2
/// Step 05 (ETW Real Provider).
///
/// Defaults are deliberately development-safe:
///   - <see cref="Enabled"/> is false: nothing collects unless the host
///     opts in.
///   - <see cref="AllowRealProvider"/> is false: even when enabled,
///     the factory prefers Null/InMemory until the host explicitly
///     authorizes the real Windows backend.
///   - <see cref="DevelopmentMode"/> is true: tests and dev workflows
///     never accidentally start a Windows ETW session.
///   - Capture flags default false so test runs cannot accidentally
///     emit events even after enabling the provider.
///   - Rate/queue caps are bounded so a runaway provider cannot
///     starve the runtime event pipeline.
///
/// Anti-FP / safety guarantees:
///   - This DTO never carries malware verdicts.
///   - This DTO never carries credentials, paths, or process data.
///   - Toggling fields here NEVER authorizes quarantine, process
///     killing, PowerShell blocking, or any other destructive action.
/// </summary>
public sealed class EtwProviderConfiguration
{
    /// <summary>Master switch. When false, the factory selects a Null provider.</summary>
    public bool Enabled { get; init; }

    /// <summary>
    /// When false (default), the factory will NEVER instantiate the
    /// real Windows ETW provider — it falls back to the Null provider
    /// even on a supported Windows host. This is the primary safety
    /// gate for tests and development builds.
    /// </summary>
    public bool AllowRealProvider { get; init; }

    /// <summary>
    /// True when running inside a development / test harness. The
    /// factory uses this as an extra guard: even if
    /// <see cref="AllowRealProvider"/> is somehow true, a development
    /// process will still fall back to the Null provider unless
    /// <see cref="ForceRealProviderInDevelopment"/> is also true.
    /// </summary>
    public bool DevelopmentMode { get; init; } = true;

    /// <summary>
    /// Escape hatch that only takes effect when <see cref="DevelopmentMode"/>
    /// is true. Off by default. Exists for explicit, opt-in dev-loop
    /// experimentation by an operator who has manually accepted that
    /// real ETW is about to run.
    /// </summary>
    public bool ForceRealProviderInDevelopment { get; init; }

    /// <summary>Capture process-start events when supported by the backend.</summary>
    public bool CaptureProcessStart { get; init; }

    /// <summary>Capture process command-line events when supported by the backend.</summary>
    public bool CaptureCommandLine { get; init; }

    /// <summary>
    /// Apply conservative PowerShell command-line indicators (encoded,
    /// hidden, dynamic-exec). Has no effect when
    /// <see cref="CaptureCommandLine"/> is false.
    /// </summary>
    public bool CapturePowerShellSignals { get; init; }

    /// <summary>
    /// Soft cap on events the provider may publish per second. Excess
    /// events are dropped and counted in health. Bounded by
    /// <see cref="WithSafeDefaults"/> so a misconfiguration cannot
    /// starve the pipeline.
    /// </summary>
    public int MaxEventsPerSecond { get; init; } = 100;

    /// <summary>
    /// Soft cap on internal in-flight queue size. Excess events are
    /// dropped and counted in health.
    /// </summary>
    public int MaxQueueSize { get; init; } = 1024;

    /// <summary>
    /// When true, command-line strings are passed through the
    /// centralized sanitizer hook before being placed into a runtime
    /// event. Default true — disabling this is for low-level tests only.
    /// </summary>
    public bool SanitizeCommandLines { get; init; } = true;

    /// <summary>Returns a config that is provably safe in tests / dev runs.</summary>
    public static EtwProviderConfiguration DevelopmentSafe() => new()
    {
        Enabled = false,
        AllowRealProvider = false,
        DevelopmentMode = true,
        ForceRealProviderInDevelopment = false,
        CaptureProcessStart = false,
        CaptureCommandLine = false,
        CapturePowerShellSignals = false,
        MaxEventsPerSecond = 100,
        MaxQueueSize = 1024,
        SanitizeCommandLines = true,
    };

    /// <summary>
    /// Returns a config that an InMemory provider can use to exercise
    /// the full mapping path deterministically without ever touching
    /// the OS.
    /// </summary>
    public static EtwProviderConfiguration InMemoryForTests() => new()
    {
        Enabled = true,
        AllowRealProvider = false,
        DevelopmentMode = true,
        ForceRealProviderInDevelopment = false,
        CaptureProcessStart = true,
        CaptureCommandLine = true,
        CapturePowerShellSignals = true,
        MaxEventsPerSecond = 1_000,
        MaxQueueSize = 1024,
        SanitizeCommandLines = true,
    };

    /// <summary>
    /// Returns a copy with values clamped into a safe range. Negative
    /// or zero values are replaced with safe defaults so callers
    /// cannot accidentally disable bounding.
    /// </summary>
    public EtwProviderConfiguration WithSafeDefaults()
    {
        return new EtwProviderConfiguration
        {
            Enabled = Enabled,
            AllowRealProvider = AllowRealProvider,
            DevelopmentMode = DevelopmentMode,
            ForceRealProviderInDevelopment = ForceRealProviderInDevelopment,
            CaptureProcessStart = CaptureProcessStart,
            CaptureCommandLine = CaptureCommandLine,
            CapturePowerShellSignals = CapturePowerShellSignals,
            MaxEventsPerSecond = MaxEventsPerSecond <= 0 ? 100 : Math.Min(MaxEventsPerSecond, 100_000),
            MaxQueueSize = MaxQueueSize <= 0 ? 1024 : Math.Min(MaxQueueSize, 1_000_000),
            SanitizeCommandLines = SanitizeCommandLines,
        };
    }
}
