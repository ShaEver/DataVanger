using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.Engine.Remediation.Planning;

/// <summary>One ordered step of a remediation plan: a zero-based index plus the
/// action's full safety descriptor.</summary>
public sealed record RemediationPlanStep(int Order, RemediationActionDescriptor Action);

/// <summary>
/// An immutable, validated remediation plan: an ordered list of steps sharing a
/// correlation id. A plan is only constructed through <see cref="RemediationPlanBuilder"/>,
/// which guarantees safe ordering. <see cref="Validate"/> re-checks the same
/// invariants so a hand-built plan cannot bypass them.
///
/// Safe-ordering invariants:
///   1. Steps run in non-decreasing <see cref="RemediationPhase"/> order
///      (Neutralize → Contain → Remove → RestoreSettings → Verify).
///   2. Every destructive Remove action on a FILE target is preceded by a
///      containment (QuarantineFile) step for the SAME target — encoding
///      "never delete before quarantine".
///   3. Every step's descriptor passes its own validation.
/// </summary>
public sealed record RemediationPlan
{
    public required RemediationCorrelationId CorrelationId { get; init; }
    public required IReadOnlyList<RemediationPlanStep> Steps { get; init; }

    public bool Validate(out string reason)
    {
        if (CorrelationId.IsEmpty)
            return Fail("Plan correlation id is empty.", out reason);
        if (Steps is null || Steps.Count == 0)
            return Fail("Plan has no steps.", out reason);

        // 1. Steps are sequentially indexed and have a target. Per-descriptor
        //    safety validation (risk/privilege/rollback/confirmation coherence)
        //    is the executor's per-step responsibility — a structurally valid
        //    plan may still contain a descriptor the executor will BLOCK. The
        //    builder validates descriptors at Add time, so builder-produced plans
        //    are still fully safe; this split lets a hand-built plan reach the
        //    executor's per-step block path instead of being rejected wholesale.
        for (int i = 0; i < Steps.Count; i++)
        {
            if (Steps[i].Action is null)
                return Fail($"Step {i} has no action.", out reason);
            if (Steps[i].Order != i)
                return Fail($"Step {i} has non-sequential order {Steps[i].Order}.", out reason);
        }

        // 2. Non-decreasing phase order.
        for (int i = 1; i < Steps.Count; i++)
        {
            if (Steps[i].Action.Phase < Steps[i - 1].Action.Phase)
                return Fail(
                    $"Out-of-order phase: step {i} ({Steps[i].Action.Phase}) precedes the later phase of step {i - 1} ({Steps[i - 1].Action.Phase}).",
                    out reason);
        }

        // 3. Deletion-after-quarantine: a file removal must be preceded by a
        //    quarantine of the same target.
        var quarantinedFiles = new HashSet<string>(StringComparer.Ordinal);
        foreach (var step in Steps)
        {
            var action = step.Action;
            if (action.Kind == RemediationActionKind.QuarantineFile)
                quarantinedFiles.Add(action.Target.MatchKey);

            bool isFileRemoval = action.Phase == RemediationPhase.Remove
                                 && action.Target.Kind == RemediationTargetKind.File
                                 && action.Kind is RemediationActionKind.DeleteFile
                                     or RemediationActionKind.HandleLockedFile
                                     or RemediationActionKind.CleanDroppedPayload;

            if (isFileRemoval && !quarantinedFiles.Contains(action.Target.MatchKey))
                return Fail(
                    $"File removal '{action.Kind}' on {action.Target} is not preceded by a QuarantineFile step for the same target (deletion-before-quarantine is forbidden).",
                    out reason);
        }

        reason = string.Empty;
        return true;

        static bool Fail(string message, out string reason)
        {
            reason = message;
            return false;
        }
    }

    public bool ContainsDestructiveIntent => Steps.Any(s => s.Action.IsDestructiveIntent);
}
