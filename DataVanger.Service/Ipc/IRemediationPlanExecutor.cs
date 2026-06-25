using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Remediation.Execution;
using DataVanger.Engine.Remediation.Planning;
using DataVanger.Engine.Remediation.Policy;
using DataVanger.Engine.Remediation.Results;

namespace DataVanger.Service.Ipc;

/// <summary>
/// Service-side adapter boundary for remediation execution. IPC handlers can
/// execute only by passing a validated plan and gate-issued permits through
/// this interface.
/// </summary>
public interface IRemediationPlanExecutor
{
    Task<RemediationExecutionResult> ExecuteAuthorizedAsync(
        RemediationPlan plan,
        IReadOnlyList<RemediationExecutionPermit> permits,
        CancellationToken cancellationToken = default);
}

public sealed class RemediationPlanExecutorAdapter : IRemediationPlanExecutor
{
    private readonly RemediationExecutor _executor;

    public RemediationPlanExecutorAdapter(RemediationExecutor executor)
        => _executor = executor;

    public Task<RemediationExecutionResult> ExecuteAuthorizedAsync(
        RemediationPlan plan,
        IReadOnlyList<RemediationExecutionPermit> permits,
        CancellationToken cancellationToken = default)
        => _executor.ExecuteAuthorizedAsync(plan, permits, cancellationToken);
}
