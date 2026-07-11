using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Ipc;

namespace DataVanger.Infrastructure.Ipc;

/// <summary>
/// Graceful-degradation client used when no service is installed / running /
/// reachable. Every request returns a structured <see cref="IpcStatusCode.ServiceUnavailable"/>
/// response. It never throws, never blocks, never retries aggressively, and
/// never spins a reconnect loop. The UI uses it to stay fully usable while the
/// service is absent.
/// </summary>
public sealed class UnavailableDataVangerServiceClient : IDataVangerServiceClient
{
    private readonly ServiceConnectionStatus _status;
    private readonly string _reason;

    public UnavailableDataVangerServiceClient(
        ServiceConnectionStatus status = ServiceConnectionStatus.NotRunning,
        string? reason = null)
    {
        _status = status;
        _reason = reason ?? "The resident DataVanger service is unavailable.";
    }

    public ServiceConnectionStatus ConnectionStatus => _status;

    public bool IsAvailable => false;

    public Task<DataVangerResponse> SendAsync(DataVangerRequest request, CancellationToken cancellationToken = default)
    {
        string requestId = request?.RequestId ?? string.Empty;
        return Task.FromResult(DataVangerResponse.Error(
            requestId,
            IpcStatusCode.ServiceUnavailable,
            _reason,
            "ServiceUnavailable"));
    }
}
