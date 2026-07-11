using System;
using DataVanger.Engine.Behavioral.Runtime;
using DataVanger.Shared.Behavioral.Runtime;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Service.Behavioral;

/// <summary>
/// Service-level composition point for the Behavioral Engine Runtime
/// Binding (Phase 2 / Step 06), mirroring
/// <see cref="DataVanger.Service.RuntimeEvents.RuntimeEventPipelineFactory"/>.
///
/// The factory is wiring only. It NEVER installs Windows services, NEVER
/// starts background loops, NEVER allocates kernel resources, and NEVER
/// authorizes remediation. The binding it creates is passive/development
/// -safe by default and produces evidence only.
/// </summary>
public static class BehavioralRuntimeBindingFactory
{
    /// <summary>
    /// Creates a development-safe, passive binding. When a pipeline is
    /// supplied the binding subscribes to it on StartAsync; otherwise it
    /// can be driven directly via <see cref="IRuntimeEventConsumer.HandleAsync"/>.
    /// </summary>
    public static BehavioralRuntimeBinding CreateDevelopmentBinding(
        IRuntimeEventPipeline? pipeline = null,
        IBehavioralRuntimeEvidenceSink? evidenceSink = null,
        Func<DateTimeOffset>? timeProvider = null)
        => new(BehavioralRuntimeBindingOptions.DevelopmentSafe(), pipeline, evidenceSink, timeProvider);

    /// <summary>Creates a fully-disabled binding (wired but inert).</summary>
    public static BehavioralRuntimeBinding CreateDisabledBinding(
        IRuntimeEventPipeline? pipeline = null)
        => new(BehavioralRuntimeBindingOptions.Disabled(), pipeline);

    /// <summary>Creates a binding from caller-supplied options (clamped to safe defaults).</summary>
    public static BehavioralRuntimeBinding Create(
        BehavioralRuntimeBindingOptions options,
        IRuntimeEventPipeline? pipeline = null,
        IBehavioralRuntimeEvidenceSink? evidenceSink = null,
        Func<DateTimeOffset>? timeProvider = null)
        => new(options, pipeline, evidenceSink, timeProvider);
}
