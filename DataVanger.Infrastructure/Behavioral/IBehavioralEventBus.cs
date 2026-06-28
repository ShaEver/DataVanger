using System;

namespace DataVanger.Behavioral;

/// <summary>
/// Pub/sub interface for behavioral events.
///
/// Implementations MUST:
///   - never throw out of <see cref="Publish"/>,
///   - bound memory growth (drop oldest or refuse new under pressure),
///   - call subscribers on a worker thread (never on the publisher's thread).
///
/// Subscribers MUST treat handlers as best-effort — exceptions thrown
/// inside a handler must not stop the bus or other handlers.
/// </summary>
public interface IBehavioralEventBus
{
    /// <summary>Publish an event. Returns <c>false</c> when the event was dropped (e.g. queue full).</summary>
    bool Publish(BehavioralEvent ev);

    /// <summary>Register a handler. Returns a disposable that removes the handler when disposed.</summary>
    IDisposable Subscribe(Action<BehavioralEvent> handler);

    /// <summary>Total events published since process start.</summary>
    long PublishedCount { get; }

    /// <summary>Total events dropped due to backpressure / queue overflow.</summary>
    long DroppedCount { get; }
}
