using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Shared.ProtectedFiles;

/// <summary>
/// Coordinates the passive monitoring layer that consumes normalized
/// runtime file telemetry and produces conservative protected-file
/// activity evidence (Phase 2 / Step 07).
///
/// Implementations MUST:
///   - start and stop safely and idempotently;
///   - honor cancellation;
///   - support disabled / passive / development-safe modes;
///   - keep all runtime state bounded and TTL-cleaned;
///   - never quarantine, kill, suspend, block writes, or inject;
///   - never escalate activity evidence into a malware verdict.
/// </summary>
public interface IProtectedFilesActivityMonitor
{
    Task StartAsync(CancellationToken cancellationToken = default);

    Task StopAsync(CancellationToken cancellationToken = default);

    ProtectedFilesActivityHealthSnapshot GetHealthSnapshot();
}
