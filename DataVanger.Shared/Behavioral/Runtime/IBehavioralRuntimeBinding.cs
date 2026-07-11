using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Shared.Behavioral.Runtime;

/// <summary>
/// Coordinates the binding between the Runtime Event Pipeline and the
/// behavioral layer. Subscribes to normalized runtime telemetry, maps it
/// into behavioral observations, correlates short-lived process context,
/// evaluates conservative runtime behavior rules, and emits behavioral
/// evidence.
///
/// Implementations MUST:
///   - start and stop safely and idempotently;
///   - honor cancellation;
///   - support disabled / passive / development-safe modes;
///   - keep all runtime state bounded and TTL-cleaned;
///   - never quarantine, kill, suspend, block, or inject;
///   - never escalate behavioral evidence into a malware verdict.
/// </summary>
public interface IBehavioralRuntimeBinding
{
    Task StartAsync(CancellationToken cancellationToken = default);

    Task StopAsync(CancellationToken cancellationToken = default);

    BehavioralRuntimeBindingStatus GetStatus();
}
