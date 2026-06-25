using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Shared.RuntimeEvents;

/// <summary>
/// Producer-facing contract. Any module (real-time file protection,
/// scheduler, future ETW provider, future anti-ransomware analyzer,
/// service host, UI) publishes <see cref="RuntimeSecurityEvent"/>s
/// through this single surface.
///
/// Implementations MUST:
///   - never throw on null events (treat as no-op or count-as-dropped),
///   - never block indefinitely,
///   - honor cancellation,
///   - never escalate runtime events into malware verdicts.
/// </summary>
public interface IRuntimeEventPublisher
{
    ValueTask PublishAsync(RuntimeSecurityEvent runtimeEvent, CancellationToken cancellationToken = default);
}
