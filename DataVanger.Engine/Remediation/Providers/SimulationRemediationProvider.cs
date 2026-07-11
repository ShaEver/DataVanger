using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Results;
using DataVanger.Engine.Remediation.Rollback;

namespace DataVanger.Engine.Remediation.Providers;

/// <summary>
/// The ONLY remediation provider in phase 03A. It SIMULATES every action: it
/// touches no file, process, service, registry key, scheduled task, or setting,
/// and it never queues a reboot or a pending file rename. It exists to prove the
/// domain — ordering, journaling, rollback metadata — without any real effect.
///
/// Every applied descriptor is recorded in <see cref="AppliedLog"/> so tests can
/// assert exactly what the executor asked for and that it never escalated to a
/// real operation. Each created action also verifies, at apply time, that the
/// executor recorded its intent in the journal FIRST — defense in depth for the
/// journal-before-action invariant.
///
/// The type name, namespace, and <see cref="IsSimulation"/> flag make it
/// unmistakably a test/simulation double; the executor additionally refuses any
/// provider whose <see cref="IsSimulation"/> is false unless a later phase
/// explicitly opts in.
/// </summary>
public sealed class SimulationRemediationProvider : IRemediationProvider
{
    private readonly object _gate = new();
    private readonly List<RemediationActionDescriptor> _applied = new();

    public bool IsSimulation => true;

    /// <summary>Every descriptor the simulation "applied", in order. Proof that
    /// no real OS object was touched: only descriptors were recorded.</summary>
    public IReadOnlyList<RemediationActionDescriptor> AppliedLog
    {
        get { lock (_gate) { return _applied.ToArray(); } }
    }

    public IRemediationAction CreateAction(RemediationActionDescriptor descriptor)
    {
        if (descriptor is null) throw new ArgumentNullException(nameof(descriptor));
        return new SimulatedAction(this, descriptor);
    }

    private void RecordApplied(RemediationActionDescriptor descriptor)
    {
        lock (_gate) { _applied.Add(descriptor); }
    }

    private sealed class SimulatedAction : IRemediationAction
    {
        private readonly SimulationRemediationProvider _owner;

        public SimulatedAction(SimulationRemediationProvider owner, RemediationActionDescriptor descriptor)
        {
            _owner = owner;
            Descriptor = descriptor;
        }

        public RemediationActionDescriptor Descriptor { get; }

        public Task<RemediationApplyResult> ExecuteAsync(RemediationActionContext context, CancellationToken cancellationToken)
        {
            if (context is null) throw new ArgumentNullException(nameof(context));
            cancellationToken.ThrowIfCancellationRequested();

            // Defense in depth: the simulated effect refuses to "happen" unless the
            // executor already journaled this step's intent.
            if (!context.Journal.HasIntent(context.CorrelationId, context.StepOrder))
            {
                return Task.FromResult(new RemediationApplyResult
                {
                    Outcome = RemediationOutcome.Blocked,
                    Reason = "Refused: no journal intent recorded before the action ran.",
                });
            }

            // Record the descriptor (NOT a real effect) so tests can prove what was
            // asked and that nothing escalated to the OS.
            _owner.RecordApplied(Descriptor);

            // A pure verification action just reports that verification ran.
            if (Descriptor.Kind == RemediationActionKind.PostRemediationVerification)
            {
                return Task.FromResult(new RemediationApplyResult
                {
                    Outcome = RemediationOutcome.Succeeded,
                    Reason = "Simulated verification pass (no real check performed).",
                });
            }

            // A reboot-required removal reports RebootRequired without doing anything.
            if (Descriptor.Reboot == RebootRequirement.Required)
            {
                return Task.FromResult(new RemediationApplyResult
                {
                    Outcome = RemediationOutcome.RebootRequired,
                    BeforeStateRef = BeforeRef(),
                    RollbackToken = BuildRollback(context.CorrelationId),
                    Reason = "Simulated: would require a reboot to complete (nothing queued).",
                });
            }

            // Everything else: simulated success, with a rollback token for
            // reversible actions and an explicit irreversible classification
            // otherwise.
            return Task.FromResult(new RemediationApplyResult
            {
                Outcome = RemediationOutcome.Succeeded,
                BeforeStateRef = Descriptor.IsReversible ? BeforeRef() : null,
                RollbackToken = BuildRollback(context.CorrelationId),
                Reason = "Simulated success (no real effect).",
            });
        }

        private string BeforeRef() => $"sim-before:{Descriptor.Target.MatchKey}";

        private RollbackToken BuildRollback(RemediationCorrelationId correlationId)
            => Descriptor.IsReversible
                ? RollbackToken.For(Descriptor.RollbackKind, $"sim:{Descriptor.Target.MatchKey}", correlationId)
                : RollbackToken.Irreversible(correlationId);
    }
}
