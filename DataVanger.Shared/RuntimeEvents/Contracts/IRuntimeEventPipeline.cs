using System;

namespace DataVanger.Shared.RuntimeEvents;

/// <summary>
/// The combined publisher + subscription + diagnostics surface of the
/// runtime event pipeline. Implementations MUST be safe to publish to
/// from multiple producers concurrently and MUST isolate consumer
/// failures.
/// </summary>
public interface IRuntimeEventPipeline : IRuntimeEventPublisher, IDisposable
{
    /// <summary>
    /// Subscribe a consumer. The same consumer instance MUST NOT be
    /// added twice; implementations may either ignore duplicates or
    /// throw an <see cref="InvalidOperationException"/> — they MUST
    /// NOT silently double-deliver events to the same instance.
    /// </summary>
    void Subscribe(IRuntimeEventConsumer consumer);

    /// <summary>
    /// Unsubscribe a consumer. Returns true when the consumer was
    /// previously registered. Safe to call on a disposed pipeline.
    /// </summary>
    bool Unsubscribe(IRuntimeEventConsumer consumer);

    /// <summary>
    /// Snapshot of pipeline diagnostics. Cheap to call. Never throws.
    /// </summary>
    RuntimeEventPipelineHealth GetHealthSnapshot();
}
