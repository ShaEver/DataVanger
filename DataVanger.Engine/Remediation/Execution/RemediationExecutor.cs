using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Planning;
using DataVanger.Engine.Remediation.Policy;
using DataVanger.Engine.Remediation.Providers;
using DataVanger.Engine.Remediation.Results;

namespace DataVanger.Engine.Remediation.Execution;

/// <summary>Executor options. The simulation-only gate mirrors the 02B IPC ACL
/// pattern: a fail-closed flag a later phase must explicitly flip to allow a real
/// provider. Even after that opt-in, non-simulation execution must use
/// gate-issued permits from <see cref="RemediationExecutionGate"/>.</summary>
public sealed record RemediationExecutorOptions
{
    /// <summary>When false (default), the executor REFUSES any provider whose
    /// <see cref="IRemediationProvider.IsSimulation"/> is false. A later phase
    /// that introduces a real provider must set it true deliberately, and must
    /// still call <see cref="ExecuteAuthorizedAsync"/> with permits issued by the
    /// execution gate.</summary>
    public bool AllowNonSimulationProviders { get; init; } = false;

    public static RemediationExecutorOptions Default { get; } = new();
}

/// <summary>
/// Runs a validated <see cref="RemediationPlan"/> against a provider, enforcing
/// the safety contract that makes destructive execution impossible by
/// construction in phase 03A:
///
///   1. Simulation-only: a non-simulation provider is refused (fail closed)
///      unless explicitly allowed.
///   2. Per-step descriptor validation: an action with incomplete safety
///      metadata is Blocked, never run.
///   3. Journal-before-action: an Intent record is appended and confirmed
///      durable BEFORE the action runs; if the journal does not persist it, the
///      action is Blocked with no effect.
///   4. Rollback discipline: a reversible action that succeeds without producing
///      a usable rollback token is downgraded to a failure (it may not claim
///      success).
///   5. Abort-after-failure: once a step is Blocked or fails, later
///      destructive-intent steps are Skipped (non-destructive verification may
///      still run).
///
/// The executor performs no OS operations itself; all effects go through the
/// (simulation) provider.
/// </summary>
public sealed class RemediationExecutor
{
    private readonly IRemediationProvider _provider;
    private readonly IRemediationJournal _journal;
    private readonly IRemediationClock _clock;
    private readonly RemediationExecutorOptions _options;

    public RemediationExecutor(
        IRemediationProvider provider,
        IRemediationJournal journal,
        IRemediationClock? clock = null,
        RemediationExecutorOptions? options = null)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _clock = clock ?? SystemRemediationClock.Instance;
        _options = options ?? RemediationExecutorOptions.Default;

        // Fail closed: a real provider cannot be run in this phase.
        if (!_provider.IsSimulation && !_options.AllowNonSimulationProviders)
            throw new InvalidOperationException(
                "Refusing to run a non-simulation remediation provider. " +
                "Real remediation requires an explicit opt-in that does not exist in this phase.");
    }

    public Task<RemediationExecutionResult> ExecuteAsync(RemediationPlan plan, CancellationToken cancellationToken = default)
    {
        if (!_provider.IsSimulation || _options.AllowNonSimulationProviders)
        {
            throw new InvalidOperationException(
                "Direct remediation execution is simulation-only. " +
                "Non-simulation remediation must use ExecuteAuthorizedAsync with permits issued by RemediationExecutionGate.");
        }

        return ExecuteCoreAsync(plan, permits: null, cancellationToken);
    }

    public Task<RemediationExecutionResult> ExecuteAuthorizedAsync(
        RemediationPlan plan,
        IReadOnlyList<RemediationExecutionPermit> permits,
        CancellationToken cancellationToken = default)
    {
        if (permits is null) throw new ArgumentNullException(nameof(permits));
        return ExecuteCoreAsync(plan, permits, cancellationToken);
    }

    private async Task<RemediationExecutionResult> ExecuteCoreAsync(
        RemediationPlan plan,
        IReadOnlyList<RemediationExecutionPermit>? permits,
        CancellationToken cancellationToken)
    {
        if (plan is null) throw new ArgumentNullException(nameof(plan));

        // A structurally unsafe plan is refused outright (the builder already
        // guarantees safety, but the executor must not trust its input).
        if (!plan.Validate(out var planReason))
            throw new InvalidOperationException($"Refusing to execute an unsafe plan: {planReason}");

        var results = new List<RemediationActionResult>(plan.Steps.Count);
        bool abortDestructive = false;

        foreach (var step in plan.Steps)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var descriptor = step.Action;

            if (permits is not null && !HasMatchingPermit(plan.CorrelationId, descriptor, permits))
            {
                AppendOutcome(plan.CorrelationId, step.Order, descriptor,
                    "Blocked: no RemediationExecutionGate permit matched this exact action + target + correlation.");
                results.Add(Block(descriptor, "No matching execution-gate permit."));
                abortDestructive = true;
                continue;
            }

            // 5. After a prior failure, do not run further destructive-intent steps.
            if (abortDestructive && descriptor.IsDestructiveIntent)
            {
                results.Add(Skip(descriptor, "Skipped: an earlier step was blocked or failed."));
                continue;
            }

            // 2. Per-step descriptor validation.
            if (!descriptor.Validate(out var validationReason))
            {
                AppendOutcome(plan.CorrelationId, step.Order, descriptor, $"Blocked: {validationReason}");
                results.Add(Block(descriptor, validationReason));
                abortDestructive = true;
                continue;
            }

            // 3. Journal-before-action: write intent, then confirm it is durable.
            AppendIntent(plan.CorrelationId, step.Order, descriptor);
            if (!_journal.HasIntent(plan.CorrelationId, step.Order))
            {
                results.Add(Block(descriptor, "Journal did not persist the action's intent; aborting before any effect."));
                abortDestructive = true;
                continue;
            }

            var context = new RemediationActionContext
            {
                CorrelationId = plan.CorrelationId,
                StepOrder = step.Order,
                Descriptor = descriptor,
                Journal = _journal,
                Clock = _clock,
            };

            var action = _provider.CreateAction(descriptor);
            RemediationApplyResult apply = await action.ExecuteAsync(context, cancellationToken).ConfigureAwait(false);

            var result = Interpret(descriptor, apply);
            AppendOutcome(plan.CorrelationId, step.Order, descriptor,
                $"{result.Outcome}: {result.Reason}", result.RollbackToken?.Kind ?? Rollback.RollbackTokenKind.None);

            results.Add(result);

            if (result.Outcome is RemediationOutcome.Blocked
                or RemediationOutcome.FailedNoChange
                or RemediationOutcome.FailedAfterPartial)
            {
                abortDestructive = true;
            }
        }

        return new RemediationExecutionResult
        {
            CorrelationId = plan.CorrelationId,
            ActionResults = results,
        };
    }

    private static bool HasMatchingPermit(
        RemediationCorrelationId correlationId,
        RemediationActionDescriptor descriptor,
        IReadOnlyList<RemediationExecutionPermit> permits)
    {
        foreach (var permit in permits)
        {
            if (permit.CorrelationId == correlationId &&
                permit.Action == descriptor.Kind &&
                permit.Decision.IsAllowed &&
                string.Equals(permit.TargetMatchKey, descriptor.Target.MatchKey, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Maps a raw apply result to a final action result, enforcing rollback
    /// discipline (4): a reversible action that claims success must carry a
    /// usable rollback token.
    /// </summary>
    private static RemediationActionResult Interpret(RemediationActionDescriptor descriptor, RemediationApplyResult apply)
    {
        if (apply.Outcome == RemediationOutcome.Succeeded && descriptor.IsReversible)
        {
            if (apply.RollbackToken is null || !apply.RollbackToken.CanRollback)
            {
                return new RemediationActionResult
                {
                    Action = descriptor,
                    Outcome = RemediationOutcome.FailedNoChange,
                    Reason = "Reversible action reported success without a usable rollback token; treated as failure.",
                };
            }
        }

        // An irreversible action must not smuggle in a rollback token.
        if (!descriptor.IsReversible && apply.RollbackToken is { CanRollback: true })
        {
            return new RemediationActionResult
            {
                Action = descriptor,
                Outcome = RemediationOutcome.FailedNoChange,
                Reason = "Irreversible action returned a rollback token; treated as failure.",
            };
        }

        return new RemediationActionResult
        {
            Action = descriptor,
            Outcome = apply.Outcome,
            RollbackToken = apply.RollbackToken,
            Reason = apply.Reason,
        };
    }

    private void AppendIntent(RemediationCorrelationId correlationId, int order, RemediationActionDescriptor descriptor)
        => _journal.Append(new RemediationJournalRecord
        {
            CorrelationId = correlationId,
            StepOrder = order,
            EntryKind = RemediationJournalEntryKind.Intent,
            ActionKind = descriptor.Kind,
            TargetMatchKey = descriptor.Target.MatchKey,
            TimestampUtc = _clock.UtcNow,
            RollbackKind = descriptor.RollbackKind,
            BeforeStateRef = descriptor.IsReversible ? $"intent-before:{descriptor.Target.MatchKey}" : null,
        });

    private void AppendOutcome(
        RemediationCorrelationId correlationId,
        int order,
        RemediationActionDescriptor descriptor,
        string outcome,
        Rollback.RollbackTokenKind rollbackKind = Rollback.RollbackTokenKind.None)
        => _journal.Append(new RemediationJournalRecord
        {
            CorrelationId = correlationId,
            StepOrder = order,
            EntryKind = RemediationJournalEntryKind.Outcome,
            ActionKind = descriptor.Kind,
            TargetMatchKey = descriptor.Target.MatchKey,
            TimestampUtc = _clock.UtcNow,
            RollbackKind = rollbackKind,
            Outcome = outcome,
        });

    private static RemediationActionResult Block(RemediationActionDescriptor descriptor, string reason)
        => new() { Action = descriptor, Outcome = RemediationOutcome.Blocked, Reason = reason };

    private static RemediationActionResult Skip(RemediationActionDescriptor descriptor, string reason)
        => new() { Action = descriptor, Outcome = RemediationOutcome.Skipped, Reason = reason };
}
