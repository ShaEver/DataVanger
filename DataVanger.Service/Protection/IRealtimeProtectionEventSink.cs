using DataVanger.Shared.Realtime;

namespace DataVanger.Service.Protection;

/// <summary>
/// Sink for structured <see cref="RealtimeProtectionEvent"/>s emitted
/// by the orchestrator. Production wires this into the existing
/// logging / reporting / forensics surface; tests inject an in-memory
/// implementation so they can assert on the event stream.
///
/// Implementations MUST be exception-safe: throwing back into the
/// orchestrator is treated as a sink failure and silently swallowed.
/// </summary>
public interface IRealtimeProtectionEventSink
{
    void Publish(RealtimeProtectionEvent ev);
}
