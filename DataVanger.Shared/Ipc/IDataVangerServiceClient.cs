using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Shared.Ipc;

/// <summary>
/// UI-side IPC client. The UI uses this narrow surface to learn the connection
/// state and to send explicit, bounded requests. Implementations MUST degrade
/// gracefully: when the service is unavailable, <see cref="SendAsync"/> returns
/// a structured error response and never throws.
/// </summary>
public interface IDataVangerServiceClient
{
    /// <summary>Current honest connection state. Cheap; never throws.</summary>
    ServiceConnectionStatus ConnectionStatus { get; }

    /// <summary>
    /// True only when the client is connected to a real, development, or test
    /// host. False when not installed / not running / unreachable.
    /// </summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Send a request and await a structured response. Honors timeout and
    /// cancellation. Returns a structured error response for every failure
    /// mode (unavailable, timeout, cancellation, oversized) — never throws for
    /// those cases.
    /// </summary>
    Task<DataVangerResponse> SendAsync(DataVangerRequest request, CancellationToken cancellationToken = default);
}
