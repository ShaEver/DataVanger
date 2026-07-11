using System;

namespace DataVanger.Shared.Behavioral.Runtime;

/// <summary>
/// Configuration for the Behavioral Engine Runtime Binding (Phase 2 /
/// Step 06). Defaults are conservative and development-safe: bounded
/// state, TTL cleanup, no remediation authority, no background loops.
/// </summary>
public sealed class BehavioralRuntimeBindingOptions
{
    /// <summary>Master switch. When false the binding subscribes to nothing and emits no evidence.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Passive mode: the binding observes and produces evidence/health
    /// for reporting only. It NEVER takes active remediation. (The
    /// binding never takes remediation in any mode — passive mode simply
    /// labels intent and the reported state.)
    /// </summary>
    public bool PassiveMode { get; init; } = true;

    /// <summary>
    /// Development-safe mode. Deterministic, no admin requirement, fully
    /// disposable. Default true so development builds stay safe.
    /// </summary>
    public bool DevelopmentMode { get; init; } = true;

    /// <summary>Rate limit (fixed 1-minute window). Overflow events are dropped and counted.</summary>
    public int MaxEventsPerMinute { get; init; } = 6000;

    /// <summary>Maximum processes tracked in correlation state at once.</summary>
    public int MaxTrackedProcesses { get; init; } = 4096;

    /// <summary>Window during which related signals are correlated for one process.</summary>
    public TimeSpan CorrelationWindow { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Time-to-live for tracked process state before TTL cleanup removes it.</summary>
    public TimeSpan ProcessStateTtl { get; init; } = TimeSpan.FromMinutes(10);

    public bool EnableProcessLineageCorrelation { get; init; } = true;
    public bool EnablePowerShellIndicators { get; init; } = true;
    public bool EnableLolBinIndicators { get; init; } = true;
    public bool EnableRiskyPathIndicators { get; init; } = true;
    public bool EnablePersistenceIndicators { get; init; } = true;
    public bool EnableTamperIndicators { get; init; } = true;
    public bool EnableFileActivityIndicators { get; init; } = true;

    /// <summary>
    /// When true the binding may publish generated behavioral evidence
    /// back onto a runtime event pipeline (as a DetectionEvidence
    /// telemetry event) for reporting consumers. Default false to keep
    /// this phase isolated and to avoid any feedback loops.
    /// </summary>
    public bool RepublishEvidenceToPipeline { get; init; } = false;

    /// <summary>Bounded number of recent evidence items retained for snapshotting.</summary>
    public int MaxRetainedEvidence { get; init; } = 256;

    /// <summary>Bounded number of recent warnings retained for the status snapshot.</summary>
    public int MaxRetainedWarnings { get; init; } = 64;

    /// <summary>Conservative, development-safe defaults (passive).</summary>
    public static BehavioralRuntimeBindingOptions DevelopmentSafe() => new()
    {
        Enabled = true,
        PassiveMode = true,
        DevelopmentMode = true,
    };

    /// <summary>Fully disabled binding (wired but inert).</summary>
    public static BehavioralRuntimeBindingOptions Disabled() => new()
    {
        Enabled = false,
        PassiveMode = true,
        DevelopmentMode = true,
    };

    /// <summary>Passive production-style binding (still never acts; evidence only).</summary>
    public static BehavioralRuntimeBindingOptions Passive() => new()
    {
        Enabled = true,
        PassiveMode = true,
        DevelopmentMode = false,
    };

    /// <summary>
    /// Returns a copy with values clamped into safe ranges so callers
    /// cannot accidentally disable bounding or TTL cleanup.
    /// </summary>
    public BehavioralRuntimeBindingOptions WithSafeDefaults()
    {
        return new BehavioralRuntimeBindingOptions
        {
            Enabled = Enabled,
            PassiveMode = PassiveMode,
            DevelopmentMode = DevelopmentMode,
            MaxEventsPerMinute = MaxEventsPerMinute <= 0 ? 6000 : Math.Min(MaxEventsPerMinute, 1_000_000),
            MaxTrackedProcesses = MaxTrackedProcesses <= 0 ? 4096 : Math.Min(MaxTrackedProcesses, 1_000_000),
            CorrelationWindow = ClampWindow(CorrelationWindow, TimeSpan.FromMinutes(5)),
            ProcessStateTtl = ClampWindow(ProcessStateTtl, TimeSpan.FromMinutes(10)),
            EnableProcessLineageCorrelation = EnableProcessLineageCorrelation,
            EnablePowerShellIndicators = EnablePowerShellIndicators,
            EnableLolBinIndicators = EnableLolBinIndicators,
            EnableRiskyPathIndicators = EnableRiskyPathIndicators,
            EnablePersistenceIndicators = EnablePersistenceIndicators,
            EnableTamperIndicators = EnableTamperIndicators,
            EnableFileActivityIndicators = EnableFileActivityIndicators,
            RepublishEvidenceToPipeline = RepublishEvidenceToPipeline,
            MaxRetainedEvidence = MaxRetainedEvidence <= 0 ? 256 : Math.Min(MaxRetainedEvidence, 100_000),
            MaxRetainedWarnings = MaxRetainedWarnings <= 0 ? 64 : Math.Min(MaxRetainedWarnings, 4096),
        };
    }

    private static TimeSpan ClampWindow(TimeSpan value, TimeSpan fallback)
    {
        if (value <= TimeSpan.Zero) return fallback;
        // Cap to a sane upper bound to keep TTL meaningful.
        var max = TimeSpan.FromHours(24);
        return value > max ? max : value;
    }
}
