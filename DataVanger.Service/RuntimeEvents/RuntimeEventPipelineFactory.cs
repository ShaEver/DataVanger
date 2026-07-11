using DataVanger.Engine.RuntimeEvents;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Service.RuntimeEvents;

/// <summary>
/// Service-level composition point introduced in Phase 2 Step 04
/// (Runtime Event Pipeline). The factory exists so future phases —
/// ETW telemetry, behavioral engine adapter, anti-ransomware analyzer,
/// reporting/forensics sinks, UI status — can obtain a pipeline through
/// a single, development-safe entry point without depending on engine
/// internals.
///
/// This factory NEVER installs Windows services, NEVER starts
/// background loops, NEVER allocates kernel resources, and NEVER
/// authorizes remediation. It is wiring only.
/// </summary>
public static class RuntimeEventPipelineFactory
{
    /// <summary>
    /// Returns a development-safe pipeline: inline dispatch, bounded
    /// queue, no background work, no admin requirement.
    /// </summary>
    public static IRuntimeEventPipeline CreateDevelopmentPipeline()
        => new InMemoryRuntimeEventPipeline(RuntimeEventPipelineOptions.DevelopmentSafe());

    /// <summary>
    /// Returns a fully-disabled pipeline. Useful when the service is
    /// degraded or when a host wants to wire dependencies without
    /// actually delivering events.
    /// </summary>
    public static IRuntimeEventPipeline CreateDisabledPipeline()
        => new InMemoryRuntimeEventPipeline(RuntimeEventPipelineOptions.Disabled());

    /// <summary>
    /// Returns a pipeline configured by the caller. Options are
    /// normalized via <see cref="RuntimeEventPipelineOptions.WithSafeDefaults"/>
    /// to prevent accidental unbounded growth.
    /// </summary>
    public static IRuntimeEventPipeline Create(RuntimeEventPipelineOptions options)
        => new InMemoryRuntimeEventPipeline(options);
}
