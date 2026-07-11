namespace DataVanger.SelfProtection;

/// <summary>
/// Sink for tamper events emitted by the Self-Protection subsystem.
///
/// Implementations MUST:
///   - never throw out of <see cref="Publish"/> (swallow + log instead),
///   - be safe to call from multiple threads,
///   - never escalate an event into a malware verdict on their own.
///
/// The default sink is <see cref="InMemoryTamperEventSink"/>; a separate
/// adapter (<see cref="BehavioralTamperBridge"/>) forwards normalized
/// events onto the behavioral bus when the manager is wired to one.
/// </summary>
public interface ITamperEventSink
{
    /// <summary>Record a tamper event. Returns true if the event was accepted.</summary>
    bool Publish(TamperEvent ev);
}
