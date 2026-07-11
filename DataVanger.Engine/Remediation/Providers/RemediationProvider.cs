using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Results;
using DataVanger.Engine.Remediation.Rollback;

namespace DataVanger.Engine.Remediation.Providers;

/// <summary>
/// Per-action execution context. Carries the correlation id, the step order, the
/// descriptor, a READ view of the journal (so an action can verify its intent was
/// recorded before acting), and the clock. It never carries a way to reach the
/// real OS.
/// </summary>
public sealed record RemediationActionContext
{
    public required RemediationCorrelationId CorrelationId { get; init; }
    public required int StepOrder { get; init; }
    public required RemediationActionDescriptor Descriptor { get; init; }
    public required IRemediationJournal Journal { get; init; }
    public required IRemediationClock Clock { get; init; }
}

/// <summary>The raw result an action/provider returns to the executor.</summary>
public sealed record RemediationApplyResult
{
    public required RemediationOutcome Outcome { get; init; }
    public RollbackToken? RollbackToken { get; init; }
    public string? BeforeStateRef { get; init; }
    public string Reason { get; init; } = string.Empty;
}

/// <summary>
/// A single remediation action bound to its descriptor. The executor runs actions;
/// concrete actions delegate their effect to a provider. In phase 03A the only
/// implementation is the simulation action, which touches nothing.
/// </summary>
public interface IRemediationAction
{
    RemediationActionDescriptor Descriptor { get; }
    Task<RemediationApplyResult> ExecuteAsync(RemediationActionContext context, CancellationToken cancellationToken);
}

/// <summary>
/// The OS-effect seam. A provider turns a descriptor into a runnable
/// <see cref="IRemediationAction"/>. <see cref="IsSimulation"/> declares whether
/// the provider performs real effects. In phase 03A the ONLY implementation is
/// <see cref="SimulationRemediationProvider"/> (IsSimulation == true); there is no
/// production provider, and the executor refuses a non-simulation provider unless
/// a later phase explicitly opts in. This is what makes destructive execution
/// impossible by construction here.
/// </summary>
public interface IRemediationProvider
{
    bool IsSimulation { get; }
    IRemediationAction CreateAction(RemediationActionDescriptor descriptor);
}
