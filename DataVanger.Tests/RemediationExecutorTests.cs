using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Execution;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Planning;
using DataVanger.Engine.Remediation.Policy;
using DataVanger.Engine.Remediation.Providers;
using DataVanger.Engine.Remediation.Results;
using DataVanger.Engine.Remediation.Rollback;
using DataVanger.Shared.Quarantine;
using Xunit;

// Phase 03A — executor tests over fakes. These prove the executor enforces the
// safety contract that makes destructive execution impossible by construction.
public class RemediationExecutorTests
{
    private static RemediationTarget F(string p) => new(RemediationTargetKind.File, p);
    private static RemediationTarget Proc(string pid) => new(RemediationTargetKind.Process, pid);

    private sealed class FixedClock : IRemediationClock
    {
        public DateTimeOffset UtcNow { get; set; } = new(2026, 6, 12, 0, 0, 0, TimeSpan.Zero);
    }

    /// <summary>A provider whose IsSimulation lies (false) but does nothing —
    /// used to prove the executor refuses non-simulation providers.</summary>
    private sealed class FakeRealProvider : IRemediationProvider
    {
        public bool IsSimulation => false;
        public IRemediationAction CreateAction(RemediationActionDescriptor descriptor)
            => throw new InvalidOperationException("Must never be created in this phase.");
    }

    /// <summary>A journal that silently drops appends (never persists) — used to
    /// prove the executor aborts before any effect when intent is not durable.</summary>
    private sealed class DropJournal : IRemediationJournal
    {
        public void Append(RemediationJournalRecord record) { /* intentionally drops */ }
        public IReadOnlyList<RemediationJournalRecord> All() => Array.Empty<RemediationJournalRecord>();
        public IReadOnlyList<RemediationJournalRecord> ForCorrelation(RemediationCorrelationId id) => Array.Empty<RemediationJournalRecord>();
        public bool HasIntent(RemediationCorrelationId id, int order) => false;
    }

    /// <summary>A provider whose action lies about success without a rollback
    /// token — used to prove rollback discipline downgrades it to a failure.</summary>
    private sealed class LyingProvider : IRemediationProvider
    {
        public bool IsSimulation => true;
        public IRemediationAction CreateAction(RemediationActionDescriptor descriptor) => new LyingAction(descriptor);

        private sealed class LyingAction : IRemediationAction
        {
            public LyingAction(RemediationActionDescriptor d) => Descriptor = d;
            public RemediationActionDescriptor Descriptor { get; }
            public Task<RemediationApplyResult> ExecuteAsync(RemediationActionContext c, CancellationToken ct)
                => Task.FromResult(new RemediationApplyResult { Outcome = RemediationOutcome.Succeeded }); // no token!
        }
    }

    /// <summary>A provider whose action tries to attach rollback metadata to an
    /// irreversible action — used to prove the executor refuses that claim.</summary>
    private sealed class RollbackSmugglingProvider : IRemediationProvider
    {
        public bool IsSimulation => true;
        public IRemediationAction CreateAction(RemediationActionDescriptor descriptor) => new SmugglingAction(descriptor);

        private sealed class SmugglingAction : IRemediationAction
        {
            public SmugglingAction(RemediationActionDescriptor d) => Descriptor = d;
            public RemediationActionDescriptor Descriptor { get; }

            public Task<RemediationApplyResult> ExecuteAsync(RemediationActionContext c, CancellationToken ct)
                => Task.FromResult(new RemediationApplyResult
                {
                    Outcome = RemediationOutcome.Succeeded,
                    RollbackToken = RollbackToken.For(RollbackTokenKind.QuarantineRestore, "not-valid-for-this-action", c.CorrelationId),
                });
        }
    }

    private static RemediationPlan ContainThenRemovePlan() =>
        new RemediationPlanBuilder()
            .Add(RemediationActionKind.KillProcessTree, Proc("4321"))
            .Add(RemediationActionKind.QuarantineFile, F(@"C:\t\evil.exe"))
            .Add(RemediationActionKind.DeleteFile, F(@"C:\t\evil.exe"))
            .Add(RemediationActionKind.PostRemediationVerification, F(@"C:\t\evil.exe"))
            .Build();

    // ── Happy path over the simulation provider ─────────────────────────────

    [Fact]
    public async Task Execute_SimulatedPlan_RunsAllStepsInOrder_WithNoRealEffect()
    {
        var provider = new SimulationRemediationProvider();
        var journal = new InMemoryRemediationJournal();
        var executor = new RemediationExecutor(provider, journal, new FixedClock());
        var plan = ContainThenRemovePlan();

        var result = await executor.ExecuteAsync(plan);

        Assert.True(result.AllSucceeded, string.Join("; ", result.ActionResults.Select(r => $"{r.Action.Kind}:{r.Outcome}:{r.Reason}")));
        // The provider only RECORDED descriptors — proof of no real OS effect.
        Assert.Equal(
            new[]
            {
                RemediationActionKind.KillProcessTree,
                RemediationActionKind.QuarantineFile,
                RemediationActionKind.DeleteFile,
                RemediationActionKind.PostRemediationVerification,
            },
            provider.AppliedLog.Select(d => d.Kind).ToArray());
    }

    [Fact]
    public async Task Execute_ReversibleActions_ProduceRollbackTokens()
    {
        var provider = new SimulationRemediationProvider();
        var journal = new InMemoryRemediationJournal();
        var executor = new RemediationExecutor(provider, journal, new FixedClock());

        var result = await executor.ExecuteAsync(ContainThenRemovePlan());

        var quarantine = result.ActionResults.Single(r => r.Action.Kind == RemediationActionKind.QuarantineFile);
        Assert.True(quarantine.RollbackToken!.CanRollback);
        Assert.Equal(RollbackTokenKind.QuarantineRestore, quarantine.RollbackToken.Kind);

        // The irreversible kill produces an explicit non-rollbackable token.
        var kill = result.ActionResults.Single(r => r.Action.Kind == RemediationActionKind.KillProcessTree);
        Assert.False(kill.RollbackToken?.CanRollback ?? false);
    }

    // ── Journal-before-action ────────────────────────────────────────────────

    [Fact]
    public async Task Execute_WritesIntentBeforeOutcome_ForEveryStep()
    {
        var provider = new SimulationRemediationProvider();
        var journal = new InMemoryRemediationJournal();
        var executor = new RemediationExecutor(provider, journal, new FixedClock());
        var plan = ContainThenRemovePlan();

        await executor.ExecuteAsync(plan);

        var records = journal.ForCorrelation(plan.CorrelationId);
        foreach (var step in plan.Steps)
        {
            var ordered = records.Where(r => r.StepOrder == step.Order).ToList();
            Assert.Equal(2, ordered.Count); // intent + outcome
            Assert.Equal(RemediationJournalEntryKind.Intent, ordered[0].EntryKind);
            Assert.Equal(RemediationJournalEntryKind.Outcome, ordered[1].EntryKind);
        }
    }

    [Fact]
    public async Task Execute_WhenJournalDropsIntent_BlocksBeforeAnyEffect()
    {
        var provider = new SimulationRemediationProvider();
        var executor = new RemediationExecutor(provider, new DropJournal(), new FixedClock());

        var result = await executor.ExecuteAsync(ContainThenRemovePlan());

        // First step blocked because intent was not durable; provider never applied anything.
        Assert.Equal(RemediationOutcome.Blocked, result.ActionResults[0].Outcome);
        Assert.Empty(provider.AppliedLog);
        // Later destructive steps are skipped, not run.
        Assert.Contains(result.ActionResults, r => r.Outcome == RemediationOutcome.Skipped);
    }

    // ── Simulation-only gate (fail closed) ──────────────────────────────────

    [Fact]
    public void Constructor_RefusesNonSimulationProvider_ByDefault()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            new RemediationExecutor(new FakeRealProvider(), new InMemoryRemediationJournal()));
        Assert.Contains("non-simulation", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Constructor_AllowsNonSimulationProvider_OnlyWithExplicitOptIn()
    {
        // The opt-in exists for later phases; constructing does not throw.
        var executor = new RemediationExecutor(
            new FakeRealProvider(),
            new InMemoryRemediationJournal(),
            new FixedClock(),
            new RemediationExecutorOptions { AllowNonSimulationProviders = true });
        Assert.NotNull(executor);
    }

    [Fact]
    public async Task Execute_DirectPath_WithNonSimulationOptIn_StillRequiresExecutionGate()
    {
        var executor = new RemediationExecutor(
            new FakeRealProvider(),
            new InMemoryRemediationJournal(),
            new FixedClock(),
            new RemediationExecutorOptions { AllowNonSimulationProviders = true });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => executor.ExecuteAsync(ContainThenRemovePlan()));
        Assert.Contains("RemediationExecutionGate", ex.Message);
    }

    [Fact]
    public async Task ExecuteAuthorized_BlocksStep_WithoutMatchingExecutionGatePermit()
    {
        var provider = new SimulationRemediationProvider();
        var journal = new InMemoryRemediationJournal();
        var executor = new RemediationExecutor(provider, journal, new FixedClock());
        var plan = new RemediationPlanBuilder()
            .Add(RemediationActionKind.QuarantineFile, F(@"C:\t\evil.exe"))
            .Build();

        var mismatchedPermit = AuthorizePermit(plan.CorrelationId, RemediationActionKind.QuarantineFile, F(@"C:\t\other.exe").MatchKey);

        var result = await executor.ExecuteAuthorizedAsync(plan, new[] { mismatchedPermit });

        Assert.Equal(RemediationOutcome.Blocked, result.ActionResults[0].Outcome);
        Assert.Empty(provider.AppliedLog);
    }

    [Fact]
    public async Task ExecuteAuthorized_RunsStep_WithMatchingExecutionGatePermit()
    {
        var provider = new SimulationRemediationProvider();
        var executor = new RemediationExecutor(provider, new InMemoryRemediationJournal(), new FixedClock());
        var plan = new RemediationPlanBuilder()
            .Add(RemediationActionKind.QuarantineFile, F(@"C:\t\evil.exe"))
            .Build();

        var permit = AuthorizePermit(plan.CorrelationId, RemediationActionKind.QuarantineFile, plan.Steps[0].Action.Target.MatchKey);

        var result = await executor.ExecuteAuthorizedAsync(plan, new[] { permit });

        Assert.True(result.AllSucceeded);
        Assert.Single(provider.AppliedLog);
    }

    // ── Rollback discipline ──────────────────────────────────────────────────

    [Fact]
    public async Task Execute_ReversibleActionWithoutRollbackToken_IsDowngradedToFailure()
    {
        var journal = new InMemoryRemediationJournal();
        var executor = new RemediationExecutor(new LyingProvider(), journal, new FixedClock());

        // A single reversible quarantine action (which the lying provider runs
        // without producing a rollback token).
        var plan = new RemediationPlanBuilder()
            .Add(RemediationActionKind.QuarantineFile, F(@"C:\t\evil.exe"))
            .Build();

        var result = await executor.ExecuteAsync(plan);

        Assert.Equal(RemediationOutcome.FailedNoChange, result.ActionResults[0].Outcome);
        Assert.Contains("rollback token", result.ActionResults[0].Reason, StringComparison.OrdinalIgnoreCase);
        Assert.True(result.AnyFailed);
    }

    [Fact]
    public async Task Execute_IrreversibleActionWithRollbackToken_IsDowngradedToFailure()
    {
        var executor = new RemediationExecutor(new RollbackSmugglingProvider(), new InMemoryRemediationJournal(), new FixedClock());
        var plan = new RemediationPlanBuilder()
            .Add(RemediationActionKind.KillProcessTree, Proc("4321"))
            .Build();

        var result = await executor.ExecuteAsync(plan);

        Assert.Equal(RemediationOutcome.FailedNoChange, result.ActionResults[0].Outcome);
        Assert.Contains("Irreversible action", result.ActionResults[0].Reason);
        Assert.Null(result.ActionResults[0].RollbackToken);
    }

    // ── Per-step descriptor validation (hand-built unsafe plan) ─────────────

    [Fact]
    public async Task Execute_StepWithInvalidDescriptor_IsBlocked_NotRun()
    {
        // Bypass the builder to inject an invalid descriptor (unspecified risk).
        var bad = RemediationActionCatalog.CreateDescriptor(RemediationActionKind.QuarantineFile, F(@"C:\t\evil.exe"))
            with { RiskLevel = RemediationRiskLevel.Unspecified };
        var plan = new RemediationPlan
        {
            CorrelationId = RemediationCorrelationId.New(),
            Steps = new[] { new RemediationPlanStep(0, bad) },
        };

        var provider = new SimulationRemediationProvider();
        var executor = new RemediationExecutor(provider, new InMemoryRemediationJournal(), new FixedClock());

        var result = await executor.ExecuteAsync(plan);

        Assert.Equal(RemediationOutcome.Blocked, result.ActionResults[0].Outcome);
        Assert.Empty(provider.AppliedLog); // never applied
    }

    // ── Abort-after-failure: no destructive step runs after a failure ───────

    [Fact]
    public async Task Execute_AfterFailure_SkipsLaterDestructiveSteps_ButRunsVerification()
    {
        // Build a valid plan, then run it with a provider that fails the kill
        // step, to prove later destructive steps are skipped.
        var provider = new FailFirstProvider(RemediationActionKind.KillProcessTree);
        var journal = new InMemoryRemediationJournal();
        var executor = new RemediationExecutor(provider, journal, new FixedClock());

        var result = await executor.ExecuteAsync(ContainThenRemovePlan());

        Assert.Equal(RemediationOutcome.FailedNoChange,
            result.ActionResults.Single(r => r.Action.Kind == RemediationActionKind.KillProcessTree).Outcome);
        // Quarantine and delete (destructive) are skipped after the failure.
        Assert.Equal(RemediationOutcome.Skipped,
            result.ActionResults.Single(r => r.Action.Kind == RemediationActionKind.QuarantineFile).Outcome);
        Assert.Equal(RemediationOutcome.Skipped,
            result.ActionResults.Single(r => r.Action.Kind == RemediationActionKind.DeleteFile).Outcome);
        // Verification is non-destructive and still runs.
        Assert.Equal(RemediationOutcome.Succeeded,
            result.ActionResults.Single(r => r.Action.Kind == RemediationActionKind.PostRemediationVerification).Outcome);
    }

    // ── Reboot-required is represented without queuing a reboot ─────────────

    [Fact]
    public async Task Execute_RebootRequiredAction_ReportsRebootRequired_NoQueue()
    {
        var provider = new SimulationRemediationProvider();
        var executor = new RemediationExecutor(provider, new InMemoryRemediationJournal(), new FixedClock());

        var plan = new RemediationPlanBuilder()
            .Add(RemediationActionKind.QuarantineFile, F(@"C:\t\locked.sys"))
            .Add(RemediationActionKind.HandleLockedFile, F(@"C:\t\locked.sys"))
            .Build();

        var result = await executor.ExecuteAsync(plan);

        Assert.True(result.RequiresReboot);
        var locked = result.ActionResults.Single(r => r.Action.Kind == RemediationActionKind.HandleLockedFile);
        Assert.Equal(RemediationOutcome.RebootRequired, locked.Outcome);
    }

    // ── Plan validation at the executor boundary ─────────────────────────────

    [Fact]
    public async Task Execute_UnsafeHandBuiltPlan_IsRefused()
    {
        var delete = RemediationActionCatalog.CreateDescriptor(RemediationActionKind.DeleteFile, F(@"C:\evil.exe"));
        var plan = new RemediationPlan
        {
            CorrelationId = RemediationCorrelationId.New(),
            Steps = new[] { new RemediationPlanStep(0, delete) }, // delete with no quarantine
        };

        var executor = new RemediationExecutor(new SimulationRemediationProvider(), new InMemoryRemediationJournal(), new FixedClock());

        await Assert.ThrowsAsync<InvalidOperationException>(() => executor.ExecuteAsync(plan));
    }

    /// <summary>A simulation provider that fails one specified kind (no effect),
    /// succeeds the rest — used for the abort-after-failure proof.</summary>
    private sealed class FailFirstProvider : IRemediationProvider
    {
        private readonly RemediationActionKind _failKind;
        public FailFirstProvider(RemediationActionKind failKind) => _failKind = failKind;
        public bool IsSimulation => true;
        public IRemediationAction CreateAction(RemediationActionDescriptor descriptor)
            => new Action(descriptor, _failKind);

        private sealed class Action : IRemediationAction
        {
            private readonly RemediationActionKind _failKind;
            public Action(RemediationActionDescriptor d, RemediationActionKind failKind) { Descriptor = d; _failKind = failKind; }
            public RemediationActionDescriptor Descriptor { get; }

            public Task<RemediationApplyResult> ExecuteAsync(RemediationActionContext c, CancellationToken ct)
            {
                if (Descriptor.Kind == _failKind)
                    return Task.FromResult(new RemediationApplyResult { Outcome = RemediationOutcome.FailedNoChange, Reason = "simulated failure" });

                var token = Descriptor.IsReversible
                    ? RollbackToken.For(Descriptor.RollbackKind, "sim", c.CorrelationId)
                    : RollbackToken.Irreversible(c.CorrelationId);
                return Task.FromResult(new RemediationApplyResult { Outcome = RemediationOutcome.Succeeded, RollbackToken = token });
            }
        }
    }

    private static RemediationExecutionPermit AuthorizePermit(
        RemediationCorrelationId correlationId,
        RemediationActionKind action,
        string targetMatchKey)
    {
        var authorization = new RemediationExecutionGate().Authorize(
            new RemediationPolicyRequest
            {
                CorrelationId = correlationId,
                Action = action,
                ThreatBand = QuarantineThreatClassification.ConfirmedMalware,
                HasConfirmedEvidence = true,
            },
            targetMatchKey,
            consent: null,
            nowUtc: new DateTimeOffset(2026, 6, 13, 12, 0, 0, TimeSpan.Zero));

        Assert.True(authorization.IsAuthorized, authorization.Reason);
        Assert.NotNull(authorization.Permit);
        return authorization.Permit;
    }
}
