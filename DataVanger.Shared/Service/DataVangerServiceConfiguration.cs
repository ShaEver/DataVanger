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

    /// <summary>
    /// Opt-in ETW command-line capture. Defaults OFF. Values pass through the
    /// existing bounded sanitizer before entering runtime-event metadata.
    /// </summary>
    public bool CaptureEtwCommandLine { get; init; } = false;

    /// <summary>
    /// Opt-in PowerShell indicator extraction from ETW command lines. Defaults
    /// OFF and remains heuristic-only; it never confirms malware.
    /// </summary>
    public bool CaptureEtwPowerShellSignals { get; init; } = false;

    /// <summary>
    /// Opt-in gate (default OFF) for one bounded process-memory scan pass
    /// during resident-runtime startup. The pass uses
    /// <c>MemoryScannerOptions</c> safe bounds, publishes findings as
    /// heuristic runtime events, and never starts a loop or authorizes
    /// remediation. Unsupported readers and permission failures degrade to a
    /// warning without failing service startup.
    /// </summary>
    public bool EnableMemoryScanPass { get; init; } = false;

    /// <summary>
    /// Opt-in gate (default OFF) for the real AMSI provider ingest path hosted
    /// by the SERVICE runtime only. When true AND the runtime runs in Service
    /// mode on a supported, privileged Windows host, the runtime hosts the
    /// write-only ingest named pipe that receives observations from the native
    /// <c>DataVanger.AmsiProvider.dll</c> shim (registered separately and
    /// explicitly via <c>--register-amsi-provider</c>). Those observations run
    /// the SAME <c>AmsiContentAnalyzer</c>/<c>AmsiBypassDetector</c> path as the
    /// in-memory provider and are published as evidence-only
    /// <c>ScriptObserved</c> events.
    ///
    /// Safety: this gate NEVER enables active protection, blocking, or
    /// quarantine. The native shim always returns <c>AMSI_RESULT_CLEAN</c> and
    /// only forwards a bounded content prefix; the service only observes. When
    /// the gate is on, the real provider REPLACES the in-memory provider (a
    /// single provider is hosted, so events are never duplicated). When the
    /// ingest listener cannot be hosted (non-Windows, name in use, unsupported),
    /// the runtime degrades to the in-memory provider without crashing.
    /// </summary>
    public bool EnableRealAmsiProvider { get; init; } = false;

    public static DataVangerServiceConfiguration SafeDefaults() => new();
}
