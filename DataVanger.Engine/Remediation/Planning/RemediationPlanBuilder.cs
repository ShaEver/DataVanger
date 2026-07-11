using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.Engine.Remediation.Planning;

/// <summary>
/// Builds an ordered, validated <see cref="RemediationPlan"/> from a set of
/// requested actions. The builder:
///   - stamps a fresh correlation id,
///   - sorts actions into safe phase order (stable within a phase, preserving
///     the caller's intent for ties),
///   - re-indexes the steps,
///   - validates the result and refuses to return an unsafe plan.
///
/// The builder DESCRIBES destructive intent (it produces descriptors) but never
/// touches the OS. It cannot be used to execute anything.
/// </summary>
public sealed class RemediationPlanBuilder
{
    private readonly List<RemediationActionDescriptor> _actions = new();

    /// <summary>Adds an action descriptor to the plan-in-progress. The descriptor
    /// is validated immediately so a malformed action is rejected at add time,
    /// not hidden until execution.</summary>
    public RemediationPlanBuilder Add(RemediationActionDescriptor action)
    {
        if (action is null) throw new ArgumentNullException(nameof(action));
        if (!action.Validate(out var reason))
            throw new ArgumentException($"Refusing to add an invalid action ({action.Kind}): {reason}", nameof(action));
        _actions.Add(action);
        return this;
    }

    /// <summary>Convenience: build a catalogued action descriptor and add it.</summary>
    public RemediationPlanBuilder Add(
        RemediationActionKind kind,
        RemediationTarget target,
        ConfirmationRequirement? confirmationOverride = null,
        string? summary = null)
        => Add(RemediationActionCatalog.CreateDescriptor(kind, target, confirmationOverride, summary));

    /// <summary>
    /// Produces the validated plan. Throws <see cref="InvalidOperationException"/>
    /// if the requested actions cannot form a safe plan (e.g. a file removal with
    /// no matching containment), so an unsafe plan can never escape the builder.
    /// </summary>
    public RemediationPlan Build()
    {
        if (_actions.Count == 0)
            throw new InvalidOperationException("Cannot build a remediation plan with no actions.");

        // Stable ordering by phase value. OrderBy is stable in .NET, so ties keep
        // the caller's insertion order (e.g. quarantine-before-delete intent when
        // both were added by the caller, and containment before later removes).
        var ordered = _actions
            .OrderBy(a => (int)a.Phase)
            .Select((a, i) => new RemediationPlanStep(i, a))
            .ToList();

        var plan = new RemediationPlan
        {
            CorrelationId = RemediationCorrelationId.New(),
            Steps = ordered,
        };

        if (!plan.Validate(out var reason))
            throw new InvalidOperationException($"Refusing to build an unsafe remediation plan: {reason}");

        return plan;
    }
}
