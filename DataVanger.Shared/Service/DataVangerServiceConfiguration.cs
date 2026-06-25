using System;

namespace DataVanger.Shared.Service;

/// <summary>
/// Minimal, conservative configuration model consumed by the service
/// runtime. Phase 2 Step 02 intentionally keeps the surface tiny —
/// future phases can extend it without breaking compatibility.
///
/// All properties have safe defaults so an empty or malformed
/// configuration produces a runnable, development-safe runtime.
/// </summary>
public sealed class DataVangerServiceConfiguration
{
    /// <summary>
    /// Service-level enable flag. False means the runtime starts in a
    /// fully disabled passive state, still safe and observable.
    /// </summary>
    public bool ServiceEnabled { get; init; } = true;

    /// <summary>
    /// When true, the runtime explicitly identifies itself as running in
    /// development mode regardless of how it was launched. Used by tests
    /// to assert development-safe semantics.
    /// </summary>
    public bool ForceDevelopmentMode { get; init; } = false;

    /// <summary>
    /// Enables the realtime protection placeholder module. The placeholder
    /// is registered as Passive / NotImplemented — it does NOT perform
    /// any realtime file blocking, ETW capture, or AMSI registration.
    /// This phase rejects any value that would promote it to Available.
    /// </summary>
    public bool RealtimeProtectionPlaceholderEnabled { get; init; } = false;

    /// <summary>
    /// Enables the runtime telemetry placeholder module. Same constraints
    /// as <see cref="RealtimeProtectionPlaceholderEnabled"/>: passive only.
    /// </summary>
    public bool RuntimeTelemetryPlaceholderEnabled { get; init; } = false;

    /// <summary>
    /// Opt-in gate (default OFF) for real ETW runtime telemetry hosted by the
    /// SERVICE runtime only. When true AND the runtime runs in Service mode on
    /// a supported, privileged Windows host, the runtime starts the existing,
    /// already-gated and bounded <c>WindowsEtwRuntimeProvider</c> (via
    /// <c>EtwRuntimeProviderHost</c>) and publishes process telemetry into a
    /// bounded in-process runtime-event pipeline.
    ///
    /// Safety: telemetry is heuristic-only and NEVER confirms malware. When the
    /// provider is unavailable, unprivileged, disabled by mode, or fails to
    /// start, the runtime degrades to the Null provider without crashing and
    /// continues running. This flag NEVER enables active protection, blocking,
    /// or quarantine; the runtime stays fully passive while it is false.
    /// </summary>
    public bool EnableEtwRuntimeTelemetry { get; init; } = false;

    public static DataVangerServiceConfiguration SafeDefaults() => new();
}
