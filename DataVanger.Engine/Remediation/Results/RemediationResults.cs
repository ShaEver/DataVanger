using System;
using System.Collections.Generic;
using System.Linq;
using DataVanger.Engine.Remediation.Rollback;

namespace DataVanger.Engine.Remediation.Results;

/// <summary>
/// The outcome of a single remediation action. Distinguishes the states the
/// phase requires so a user is never left unsure whether the system changed.
/// </summary>
public enum RemediationOutcome
{
    /// <summary>The action completed and (for reversible actions) produced a
    /// rollback token.</summary>
    Succeeded = 0,

    /// <summary>The action was not attempted because a precondition was not met
    /// (e.g. nothing to do). No change was made.</summary>
    Skipped,

    /// <summary>The action was refused by validation/safety before any attempt.
    /// No change was made.</summary>
    Blocked,

    /// <summary>The action was attempted, failed, and left the target unchanged.</summary>
    FailedNoChange,

    /// <summary>The action failed after a partial change; the journal holds what
    /// was done so it can be rolled back / inspected.</summary>
    FailedAfterPartial,

    /// <summary>The action's effect needs a reboot to complete; nothing
    /// destructive happened yet.</summary>
    RebootRequired,

    /// <summary>The action completed but a verification pass is still required to
    /// confirm the threat is gone.</summary>
    VerificationRequired,
}

/// <summary>The result of one action: its descriptor, outcome, optional rollback
/// token (present for a succeeded reversible action), a reason, and the journal
/// record ids that bracket it.</summary>
public sealed record RemediationActionResult
{
    public required RemediationActionDescriptor Action { get; init; }
    public required RemediationOutcome Outcome { get; init; }
    public RollbackToken? RollbackToken { get; init; }
    public string Reason { get; init; } = string.Empty;

    /// <summary>True for outcomes where the target was not modified at all.</summary>
    public bool IsNoChange => Outcome is RemediationOutcome.Skipped
        or RemediationOutcome.Blocked
        or RemediationOutcome.FailedNoChange
        or RemediationOutcome.RebootRequired;

    public bool Succeeded => Outcome == RemediationOutcome.Succeeded;
}

/// <summary>
/// The aggregate result of executing a plan: every per-action result plus a
/// roll-up. Preserves completed/skipped/failed detail (never collapses to a
/// single generic failure).
/// </summary>
public sealed record RemediationExecutionResult
{
    public required RemediationCorrelationId CorrelationId { get; init; }
    public required IReadOnlyList<RemediationActionResult> ActionResults { get; init; }

    public bool AllSucceeded => ActionResults.All(r => r.Succeeded);

    public bool AnyFailed => ActionResults.Any(r =>
        r.Outcome is RemediationOutcome.FailedNoChange or RemediationOutcome.FailedAfterPartial);

    public bool RequiresReboot => ActionResults.Any(r => r.Outcome == RemediationOutcome.RebootRequired);

    public bool RequiresVerification => ActionResults.Any(r => r.Outcome == RemediationOutcome.VerificationRequired);

    public int SucceededCount => ActionResults.Count(r => r.Succeeded);
}
