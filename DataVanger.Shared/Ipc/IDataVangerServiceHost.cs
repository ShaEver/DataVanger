using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Shared.Ipc;

/// <summary>
/// Service-side IPC entry point. A host receives a validated request envelope
/// and returns a structured response. Implementations (the command router)
/// MUST:
///   - never throw across this boundary for normal failures (return a
///     structured <see cref="DataVangerResponse"/> instead);
///   - reject unknown / unsupported / malformed requests with structured
///     errors;
///   - honor cancellation;
///   - never require admin privileges, a real installed service, or a network.
/// </summary>
public interface IDataVangerServiceHost
{
    Task<DataVangerResponse> HandleAsync(DataVangerRequest request, CancellationToken cancellationToken = default);
}
