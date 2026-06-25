using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Remediation;

namespace DataVanger.ViewModels;

/// <summary>
/// The Removal Center's only path to remediation: a typed, DTO-in / DTO-out
/// gateway over the policy-gated IPC surface. The WPF process never references
/// the engine and never executes remediation locally — it asks the service and
/// renders the answer.
/// </summary>
public interface IRemovalCenterService
{
    /// <summary>Whether the resident service is reachable for remediation.</summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Send one execution request to the service and return its response, or
    /// <c>null</c> when the service is unreachable or the response is missing or
    /// malformed (treated as a closed, non-authorizing failure by the caller).
    /// </summary>
    Task<RemediationExecutionResponseDto?> ExecuteAsync(
        RemediationExecutionRequestDto request,
        CancellationToken cancellationToken = default);
}
