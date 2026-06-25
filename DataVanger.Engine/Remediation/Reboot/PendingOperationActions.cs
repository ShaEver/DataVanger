using System;
using System.Collections.Generic;
using System.Linq;
using DataVanger.Engine.Remediation.Verification;

namespace DataVanger.Engine.Remediation.Reboot;

/// <summary>Probe for whether a target file is still present (post-reboot check).
/// Abstracted so replay/verify never touch the real filesystem in tests.</summary>
public interface IFilePresenceProbe
{
    bool Exists(string path);
}

/// <summary>Outcome of attempting to cancel a pending operation.</summary>
public enum CancelOutcome
{
    Canceled = 0,
    NotFound,
    BlockedAlreadyReplayed,
    BlockedTerminalState,
    AlreadyCanceled,
}

/// <summary>
/// Cancels a queued pending operation BEFORE reboot. Once an operation has been
/// replayed (i.e. the reboot happened and it was applied) it can no longer be
/// canceled — cancellation is a pre-reboot control only.
/// </summary>
public sealed class CancelPendingOperationAction
{
    private readonly IPendingRebootOperationStore _store;
    private readonly IPendingFileOperationProvider _provider;
    private readonly IRemediationClock _clock;

    public CancelPendingOperationAction(IPendingRebootOperationStore store, IPendingFileOperationProvider provider, IRemediationClock? clock = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _clock = clock ?? SystemRemediationClock.Instance;
    }

    public CancelOutcome Cancel(PendingOperationId id)
    {
        var op = _store.Get(id);
        if (op is null) return CancelOutcome.NotFound;
        var terminal = OutcomeForNonQueuedStatus(op.Status);
        if (terminal is not null) return terminal.Value;

        bool changed = _store.TryTransition(id, PendingOperationStatus.Canceled, "Canceled before reboot", _clock.UtcNow);
        if (!changed)
        {
            var latest = _store.Get(id);
            return latest is null
                ? CancelOutcome.NotFound
                : OutcomeForNonQueuedStatus(latest.Status) ?? CancelOutcome.BlockedTerminalState;
        }

        // Clear the (fake) OS-deferred delete so it will NOT run on the next boot.
        _provider.CancelQueuedDelete(op.TargetPath);
        return CancelOutcome.Canceled;
    }

    private static CancelOutcome? OutcomeForNonQueuedStatus(PendingOperationStatus status) => status switch
    {
        PendingOperationStatus.Queued => null,
        PendingOperationStatus.Canceled => CancelOutcome.AlreadyCanceled,
        PendingOperationStatus.Replayed or PendingOperationStatus.Verified => CancelOutcome.BlockedAlreadyReplayed,
        PendingOperationStatus.Failed => CancelOutcome.BlockedTerminalState,
        _ => CancelOutcome.BlockedTerminalState,
    };
}

/// <summary>What happened to one operation during a replay pass.</summary>
public sealed record ReplayFinding(PendingOperationId Id, PendingOperationStatus Status, string Detail);

/// <summary>
/// Idempotent post-reboot replay. For each still-Queued operation it verifies the
/// target is gone after restart:
///   - target absent  -> transition Queued to Replayed (observed absent; verification
///                       must still confirm and mark Verified);
///   - target present -> transition Queued to Failed (the boot delete did not happen);
///                       honest "not removed".
/// Re-running the replay is a no-op for any operation that is no longer Queued, so
/// a service that starts twice after reboot cannot double-apply anything.
/// </summary>
public sealed class PendingOperationReplayer
{
    private readonly IPendingRebootOperationStore _store;
    private readonly IFilePresenceProbe _presence;
    private readonly IRemediationClock _clock;

    public PendingOperationReplayer(IPendingRebootOperationStore store, IFilePresenceProbe presence, IRemediationClock? clock = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _presence = presence ?? throw new ArgumentNullException(nameof(presence));
        _clock = clock ?? SystemRemediationClock.Instance;
    }

    public IReadOnlyList<ReplayFinding> Replay()
    {
        var findings = new List<ReplayFinding>();
        foreach (var op in _store.List())
        {
            if (op.Status != PendingOperationStatus.Queued)
            {
                // Idempotent: nothing to do for an op that was already
                // replayed/canceled/verified/failed.
                findings.Add(new ReplayFinding(op.Id, op.Status, "No-op (not queued)."));
                continue;
            }

            bool stillPresent = _presence.Exists(op.TargetPath);
            if (stillPresent)
            {
                _store.TryTransition(op.Id, PendingOperationStatus.Failed, "Target still present after reboot.", _clock.UtcNow);
                findings.Add(new ReplayFinding(op.Id, PendingOperationStatus.Failed, "Target still present after reboot; not removed."));
            }
            else
            {
                _store.TryTransition(op.Id, PendingOperationStatus.Replayed, "Target absent after reboot; pending post-remediation verification.", _clock.UtcNow);
                findings.Add(new ReplayFinding(op.Id, PendingOperationStatus.Replayed, "Target absent after reboot; pending verification."));
            }
        }
        return findings;
    }
}

/// <summary>Outcome of binding post-remediation verification back to a pending operation.</summary>
public enum PendingOperationVerificationOutcome
{
    Verified = 0,
    Failed,
    NotFound,
    BlockedNotReplayed,
    AlreadyVerified,
    AlreadyFailed,
    AlreadyCanceled,
}

/// <summary>Result of verifying one replayed pending operation.</summary>
public sealed record PendingOperationVerificationFinding(
    PendingOperationId Id,
    PendingOperationVerificationOutcome Outcome,
    PendingOperationStatus? Status,
    PostRebootVerificationResult? Verification,
    string Detail);

/// <summary>
/// Binds conservative post-remediation checks to the pending-operation state
/// machine. Only a Replayed operation can become Verified; any failed or empty
/// verification result becomes Failed so "queued/replayed" is never reported as
/// completed removal without proof.
/// </summary>
public sealed class PendingOperationVerificationAction
{
    private readonly IPendingRebootOperationStore _store;
    private readonly RemediationVerificationService _verification;
    private readonly IRemediationClock _clock;

    public PendingOperationVerificationAction(
        IPendingRebootOperationStore store,
        RemediationVerificationService verification,
        IRemediationClock? clock = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _verification = verification ?? throw new ArgumentNullException(nameof(verification));
        _clock = clock ?? SystemRemediationClock.Instance;
    }

    public PendingOperationVerificationFinding Verify(PendingOperationId id, IReadOnlyList<VerificationCheck> checks)
    {
        if (checks is null) throw new ArgumentNullException(nameof(checks));

        var op = _store.Get(id);
        if (op is null)
        {
            return new PendingOperationVerificationFinding(
                id, PendingOperationVerificationOutcome.NotFound, null, null, "Pending operation was not found.");
        }

        if (op.Status != PendingOperationStatus.Replayed)
        {
            return op.Status switch
            {
                PendingOperationStatus.Verified => new PendingOperationVerificationFinding(
                    id, PendingOperationVerificationOutcome.AlreadyVerified, op.Status, null, "Pending operation is already verified."),
                PendingOperationStatus.Failed => new PendingOperationVerificationFinding(
                    id, PendingOperationVerificationOutcome.AlreadyFailed, op.Status, null, "Pending operation already failed."),
                PendingOperationStatus.Canceled => new PendingOperationVerificationFinding(
                    id, PendingOperationVerificationOutcome.AlreadyCanceled, op.Status, null, "Pending operation was canceled before reboot."),
                _ => new PendingOperationVerificationFinding(
                    id, PendingOperationVerificationOutcome.BlockedNotReplayed, op.Status, null, "Pending operation has not been replayed yet."),
            };
        }

        var result = _verification.Verify(checks);
        if (result.IsClean)
        {
            _store.TryTransition(id, PendingOperationStatus.Verified, "Post-remediation verification passed.", _clock.UtcNow);
            return new PendingOperationVerificationFinding(
                id,
                PendingOperationVerificationOutcome.Verified,
                _store.Get(id)?.Status ?? PendingOperationStatus.Verified,
                result,
                "Post-remediation verification passed; artifact absence confirmed.");
        }

        _store.TryTransition(id, PendingOperationStatus.Failed, FailureDetail(result), _clock.UtcNow);
        return new PendingOperationVerificationFinding(
            id,
            PendingOperationVerificationOutcome.Failed,
            _store.Get(id)?.Status ?? PendingOperationStatus.Failed,
            result,
            FailureDetail(result));
    }

    private static string FailureDetail(PostRebootVerificationResult result)
    {
        if (result.Findings.Count == 0)
            return "No verification checks were supplied; operation cannot be marked clean.";

        var failures = result.Failures
            .Select(f => $"{f.Kind}:{f.Target}")
            .ToArray();

        return failures.Length == 0
            ? "Verification did not prove a clean state."
            : "Verification failed; remaining artifacts: " + string.Join("; ", failures);
    }
}
