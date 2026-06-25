using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Shared.RuntimeEvents;

/// <summary>
/// Consumer-facing contract. Subscribers receive each delivered
/// <see cref="RuntimeSecurityEvent"/> exactly once per delivery and
/// MUST treat events as telemetry — never as authorization to take
/// destructive action.
///
/// A consumer that throws does NOT crash the pipeline; the failure is
/// isolated and surfaced as a health warning. Subsequent consumers
/// still receive the event.
/// </summary>
public interface IRuntimeEventConsumer
{
    ValueTask HandleAsync(RuntimeSecurityEvent runtimeEvent, CancellationToken cancellationToken = default);
}
