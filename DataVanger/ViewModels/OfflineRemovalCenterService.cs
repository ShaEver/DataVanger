using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Remediation;

namespace DataVanger.ViewModels;

/// <summary>
/// Placeholder Removal Center gateway used while the WPF process is not yet
/// wired to a concrete <c>IDataVangerServiceClient</c>. Phase 05 introduces the
/// first UI→IPC seam; injecting the real named-pipe client is application
/// composition / a later increment (it also depends on the server registering a
/// detection context and issuing consent, which are not yet exposed over IPC).
///
/// This gateway reports the service as unavailable and returns no response, so
/// the Removal Center surfaces an honest "service unavailable" state instead of
/// fabricating a successful remediation.
/// </summary>
public sealed class OfflineRemovalCenterService : IRemovalCenterService
{
    public bool IsAvailable => false;

    public Task<RemediationExecutionResponseDto?> ExecuteAsync(
        RemediationExecutionRequestDto request,
        CancellationToken cancellationToken = default)
        => Task.FromResult<RemediationExecutionResponseDto?>(null);
}
