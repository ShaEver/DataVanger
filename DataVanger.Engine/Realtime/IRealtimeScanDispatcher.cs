using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Realtime;

namespace DataVanger.Engine.Realtime;

/// <summary>
/// Bridge between the real-time orchestrator and the existing scan
/// engine. Implementations adapt the engine's full scan/classify
/// pipeline into a single <see cref="RealtimeScanResult"/> per request,
/// honoring the existing ThreatClassificationPolicy.
///
/// Anti-FP contract:
///   - The dispatcher MUST NOT promote a verdict beyond what the
///     underlying engine + classification policy produced.
///   - <see cref="RealtimeScanResult.IsConfirmedMalware"/> may only be
///     true when the engine reports ConfirmedMalware (hash blacklist or
///     confirmed signature).
///   - Failures (engine unavailable, file vanished, cancellation) must
///     surface as Failed=true, NEVER as malware.
/// </summary>
public interface IRealtimeScanDispatcher
{
    Task<RealtimeScanResult> DispatchAsync(RealtimeScanRequest request, CancellationToken cancellationToken);
}
