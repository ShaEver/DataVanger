using System;

namespace DataVanger.Shared.RuntimeEvents;

/// <summary>
/// Configuration for the runtime event pipeline. Defaults are
/// development-safe: bounded queue, no background loops, inline
/// dispatch, no remediation authority.
/// </summary>
public sealed class RuntimeEventPipelineOptions
{
    /// <summary>
    /// Master switch. When false the pipeline behaves as if
    /// <see cref="Mode"/> were <see cref="RuntimeEventPipelineMode.Disabled"/>.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Operating mode. Defaults to <see cref="RuntimeEventPipelineMode.Development"/>.
    /// </summary>
    public RuntimeEventPipelineMode Mode { get; init; } = RuntimeEventPipelineMode.Development;

    /// <summary>
    /// Maximum number of events that may be in-flight (queued or
    /// dispatching) at one moment. Overflow events are dropped per
    /// <see cref="DropPolicy"/>. The pipeline NEVER grows memory
    /// without bound.
    /// </summary>
    public int MaxQueueSize { get; init; } = 1024;

    /// <summary>
    /// Drop policy applied when <see cref="MaxQueueSize"/> would be
    /// exceeded. Defaults to <see cref="RuntimeEventDropPolicy.DropNewest"/>.
    /// </summary>
    public RuntimeEventDropPolicy DropPolicy { get; init; } = RuntimeEventDropPolicy.DropNewest;

    /// <summary>
    /// When true the pipeline records detailed warnings (consumer
    /// exception type/message) in the health snapshot. The warning
    /// buffer is itself bounded; oldest warnings are evicted.
    /// </summary>
    public bool EnableDevelopmentDiagnostics { get; init; } = true;

    /// <summary>
    /// Reserved for a future optional adapter that translates selected
    /// runtime events into behavioral observations. Off by default to
    /// keep this phase isolated from the behavioral engine.
    /// </summary>
    public bool EnableBehavioralAdapter { get; init; } = false;

    /// <summary>
    /// Reserved for a future optional reporting sink. Off by default to
    /// keep this phase isolated from reporting/forensics.
    /// </summary>
    public bool EnableReportingSink { get; init; } = false;

    /// <summary>
    /// Maximum number of warning entries retained in the health
    /// snapshot. Keeps the warning surface bounded.
    /// </summary>
    public int MaxRetainedWarnings { get; init; } = 64;

    public static RuntimeEventPipelineOptions DevelopmentSafe() => new()
    {
        Enabled = true,
        Mode = RuntimeEventPipelineMode.Development,
        MaxQueueSize = 1024,
        DropPolicy = RuntimeEventDropPolicy.DropNewest,
        EnableDevelopmentDiagnostics = true,
        EnableBehavioralAdapter = false,
        EnableReportingSink = false,
    };

    public static RuntimeEventPipelineOptions Disabled() => new()
    {
        Enabled = false,
        Mode = RuntimeEventPipelineMode.Disabled,
    };

    /// <summary>
    /// Returns a copy with values clamped into a safe range. Negative
    /// or zero sizes are replaced with safe defaults so callers cannot
    /// accidentally disable bounding.
    /// </summary>
    public RuntimeEventPipelineOptions WithSafeDefaults()
    {
        return new RuntimeEventPipelineOptions
        {
            Enabled = Enabled,
            Mode = Mode,
            MaxQueueSize = MaxQueueSize <= 0 ? 1024 : Math.Min(MaxQueueSize, 1_000_000),
            DropPolicy = DropPolicy,
            EnableDevelopmentDiagnostics = EnableDevelopmentDiagnostics,
            EnableBehavioralAdapter = EnableBehavioralAdapter,
            EnableReportingSink = EnableReportingSink,
            MaxRetainedWarnings = MaxRetainedWarnings <= 0 ? 64 : Math.Min(MaxRetainedWarnings, 1024),
        };
    }
}
