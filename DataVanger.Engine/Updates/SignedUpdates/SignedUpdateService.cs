using System;
using System.Collections.Generic;
using System.Globalization;
using DataVanger.Shared.RuntimeEvents;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Orchestrates the signed-update workflow. Inline and synchronous: no
/// background loops, no timers, no fire-and-forget tasks. Every operation
/// returns a structured result and degrades gracefully. Update activity is
/// telemetry only and can never produce a malware verdict.
/// </summary>
public sealed class SignedUpdateService : ISignedUpdateService
{
    private enum SequenceDecision
    {
        Proceed,
        AlreadyCurrent,
        DowngradeRejected,
        SequenceConflict,
    }

    private readonly UpdatePolicy _policy;
    private readonly ISignedManifestVerifier _verifier;
    private readonly IUpdatePackageVerifier _packageVerifier;
    private readonly IUpdateStateStore _stateStore;
    private readonly IUpdateContentSink _contentSink;
    private readonly IUpdateTransport _transport;
    private readonly IRuntimeEventPublisher? _eventPublisher;
    private readonly Func<DateTimeOffset> _clock;

    private readonly object _gate = new();
    private UpdateResultKind _lastResultKind = UpdateResultKind.None;
    private string _lastMessage = string.Empty;

    public SignedUpdateService(
        UpdatePolicy policy,
        ISignedManifestVerifier verifier,
        IUpdatePackageVerifier packageVerifier,
        IUpdateStateStore stateStore,
        IUpdateContentSink contentSink,
        IUpdateTransport transport,
        IRuntimeEventPublisher? eventPublisher = null,
        Func<DateTimeOffset>? clock = null)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        _packageVerifier = packageVerifier ?? throw new ArgumentNullException(nameof(packageVerifier));
        _stateStore = stateStore ?? throw new ArgumentNullException(nameof(stateStore));
        _contentSink = contentSink ?? throw new ArgumentNullException(nameof(contentSink));
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _eventPublisher = eventPublisher;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    public UpdateApplyResult CheckAndApply()
    {
        var feedId = _policy.FeedId;

        // Disabled mode: no activity at all (no events, no state change).
        if (!_policy.IsUpdatingEnabled)
        {
            RecordLast(UpdateResultKind.Disabled, "Updates are disabled by policy.");
            return UpdateApplyResult.Failure(UpdateResultKind.Disabled, "Updates are disabled by policy.", feedId, _stateStore.GetCurrent(feedId));
        }

        try
        {
            Publish(UpdateResultKind.None, "Update check started", "Signed update check started.", RuntimeEventSeverity.Informational);

            var manifestBytes = _transport.GetManifestBytes();
            if (manifestBytes is null)
                return FailApply(UpdateResultKind.TransportUnavailable, "Transport did not provide a manifest.", feedId);

            if (!UpdateManifestJson.TryDeserialize(manifestBytes, out var manifest) || manifest is null)
                return FailApply(UpdateResultKind.ManifestMalformed, "Manifest could not be deserialized.", feedId);

            var verification = _verifier.Verify(manifest);
            if (!verification.IsValid)
                return FailApply(verification.Kind, verification.Message, feedId, manifest.Sequence);

            var canonicalSha256 = verification.CanonicalSha256 ?? string.Empty;
            var decision = EvaluateSequence(feedId, manifest.Sequence, canonicalSha256);
            switch (decision)
            {
                case SequenceDecision.AlreadyCurrent:
                    Publish(UpdateResultKind.AlreadyCurrent, "Update already current",
                        $"Sequence {manifest.Sequence} already installed.", RuntimeEventSeverity.Informational);
                    RecordLast(UpdateResultKind.AlreadyCurrent, "Already current.");
                    return UpdateApplyResult.Success(UpdateResultKind.AlreadyCurrent, feedId, manifest.Sequence, _stateStore.GetCurrent(feedId), "Already current.");
                case SequenceDecision.DowngradeRejected:
                    return FailApply(UpdateResultKind.DowngradeRejected, "Manifest sequence is lower than the installed highest.", feedId, manifest.Sequence);
                case SequenceDecision.SequenceConflict:
                    return FailApply(UpdateResultKind.SequenceConflict, "Manifest sequence equals the installed highest but the canonical hash differs.", feedId, manifest.Sequence);
            }

            // Passive check: verify only, never apply.
            if (_policy.Mode == UpdateMode.PassiveCheck)
            {
                Publish(UpdateResultKind.Accepted, "Update available (passive)",
                    $"Sequence {manifest.Sequence} verified; passive mode does not apply.", RuntimeEventSeverity.Informational);
                RecordLast(UpdateResultKind.Accepted, "Verified (passive, not applied).");
                return UpdateApplyResult.Success(UpdateResultKind.Accepted, feedId, manifest.Sequence, _stateStore.GetCurrent(feedId), "Verified (passive, not applied).");
            }

            // Fetch + validate all packages.
            var staged = new List<StagedPackage>();
            foreach (var package in manifest.Packages)
            {
                var content = _transport.GetPackageBytes(package);
                var validation = _packageVerifier.Validate(package, content, _policy);
                if (!validation.IsValid)
                {
                    if (package.Required)
                        return FailApply(validation.Kind, $"Required package '{validation.PackageId}' failed: {validation.Message}", feedId, manifest.Sequence);

                    // Optional package may fail without aborting.
                    Publish(validation.Kind, "Optional package skipped",
                        $"Optional package '{validation.PackageId}' failed: {validation.Message}", RuntimeEventSeverity.Medium);
                    continue;
                }

                staged.Add(new StagedPackage(package, content!));
            }

            // Atomic stage + commit. Any failure preserves the previous active state.
            try
            {
                _contentSink.Stage(feedId, manifest.Sequence, canonicalSha256, staged);
                _contentSink.Commit(feedId, manifest.Sequence);
            }
            catch (Exception ex)
            {
                return FailApply(UpdateResultKind.StagingFailed, "Staging/commit failed; previous active set preserved: " + ex.Message, feedId, manifest.Sequence);
            }

            var newState = new UpdateStateSnapshot
            {
                FeedId = feedId,
                HighestSequence = manifest.Sequence,
                ManifestCanonicalSha256 = canonicalSha256,
                AppliedUtc = _clock().UtcDateTime.ToString("o", CultureInfo.InvariantCulture),
            };
            try
            {
                _stateStore.Commit(newState);
            }
            catch
            {
                try { _contentSink.Restore(feedId); } catch { /* original exception wins */ }
                throw;
            }

            Publish(UpdateResultKind.Applied, "Update committed",
                $"Sequence {manifest.Sequence} committed.", RuntimeEventSeverity.Informational);
            RecordLast(UpdateResultKind.Applied, "Applied.");
            return UpdateApplyResult.Success(UpdateResultKind.Applied, feedId, manifest.Sequence, newState, "Applied.");
        }
        catch (Exception ex)
        {
            // Contain any unexpected failure as a structured result.
            return FailApply(UpdateResultKind.Failed, "Unexpected update failure: " + ex.Message, feedId);
        }
    }

    public UpdateVerificationResult CheckOnly()
    {
        var feedId = _policy.FeedId;
        if (!_policy.IsUpdatingEnabled)
            return UpdateVerificationResult.Invalid(UpdateResultKind.Disabled, "Updates are disabled by policy.", feedId);

        try
        {
            var manifestBytes = _transport.GetManifestBytes();
            if (manifestBytes is null)
                return UpdateVerificationResult.Invalid(UpdateResultKind.TransportUnavailable, "Transport did not provide a manifest.", feedId);

            if (!UpdateManifestJson.TryDeserialize(manifestBytes, out var manifest) || manifest is null)
                return UpdateVerificationResult.Invalid(UpdateResultKind.ManifestMalformed, "Manifest could not be deserialized.", feedId);

            var verification = _verifier.Verify(manifest);
            if (!verification.IsValid)
                return verification;

            var canonicalSha256 = verification.CanonicalSha256 ?? string.Empty;
            var decision = EvaluateSequence(feedId, manifest.Sequence, canonicalSha256);
            return decision switch
            {
                SequenceDecision.DowngradeRejected => UpdateVerificationResult.Invalid(UpdateResultKind.DowngradeRejected, "Manifest sequence is lower than the installed highest.", feedId, manifest.Sequence, canonicalSha256),
                SequenceDecision.SequenceConflict => UpdateVerificationResult.Invalid(UpdateResultKind.SequenceConflict, "Manifest sequence equals the installed highest but the canonical hash differs.", feedId, manifest.Sequence, canonicalSha256),
                SequenceDecision.AlreadyCurrent => UpdateVerificationResult.Valid(feedId, manifest.Sequence, canonicalSha256, UpdateResultKind.AlreadyCurrent, "Already current."),
                _ => verification,
            };
        }
        catch (Exception ex)
        {
            return UpdateVerificationResult.Invalid(UpdateResultKind.Failed, "Unexpected verification failure: " + ex.Message, feedId);
        }
    }

    public UpdateApplyResult Rollback()
    {
        var feedId = _policy.FeedId;
        if (!_policy.IsUpdatingEnabled)
        {
            RecordLast(UpdateResultKind.Disabled, "Updates are disabled by policy.");
            return UpdateApplyResult.Failure(UpdateResultKind.Disabled, "Updates are disabled by policy.", feedId, _stateStore.GetCurrent(feedId));
        }

        try
        {
            var lastKnownGood = _stateStore.GetLastKnownGood(feedId);
            if (lastKnownGood is null)
            {
                Publish(UpdateResultKind.NoRollbackAvailable, "Rollback unavailable",
                    "No last-known-good snapshot exists.", RuntimeEventSeverity.Medium);
                RecordLast(UpdateResultKind.NoRollbackAvailable, "No last-known-good snapshot.");
                return UpdateApplyResult.Failure(UpdateResultKind.NoRollbackAvailable, "No last-known-good snapshot exists.", feedId, _stateStore.GetCurrent(feedId));
            }

            _contentSink.Restore(feedId);
            if (!_stateStore.TryRollback(feedId, out var restored))
                throw new InvalidOperationException("Content restored but state LKG disappeared before commit.");

            Publish(UpdateResultKind.RollbackCompleted, "Rollback completed",
                $"Restored sequence {restored.HighestSequence}.", RuntimeEventSeverity.Medium);
            RecordLast(UpdateResultKind.RollbackCompleted, "Rolled back.");
            return UpdateApplyResult.Success(UpdateResultKind.RollbackCompleted, feedId, restored.HighestSequence, restored, "Rolled back.");
        }
        catch (Exception ex)
        {
            return UpdateApplyResult.Failure(UpdateResultKind.Failed, "Unexpected rollback failure: " + ex.Message, feedId, _stateStore.GetCurrent(feedId));
        }
    }

    public UpdateHealthSnapshot GetHealth()
    {
        var feedId = _policy.FeedId;
        var current = _stateStore.GetCurrent(feedId);
        var lastKnownGood = _stateStore.GetLastKnownGood(feedId);
        var enabled = _policy.IsUpdatingEnabled;
        var contentHealth = (_contentSink as FileSystemSignatureUpdateSink)?.GetHealth(feedId);

        UpdateResultKind lastKind;
        string lastMessage;
        lock (_gate)
        {
            lastKind = _lastResultKind;
            lastMessage = _lastMessage;
        }

        var status = !enabled
            ? "Disabled"
            : IsDegraded(lastKind) ? "Degraded" : "Healthy";

        return new UpdateHealthSnapshot
        {
            IsEnabled = enabled,
            Mode = _policy.Mode,
            FeedId = feedId,
            HighestSequence = current.HighestSequence,
            HasLastKnownGood = lastKnownGood is not null,
            ActiveVersion = contentHealth?.ActiveVersion ?? string.Empty,
            LastKnownGoodVersion = contentHealth?.LastKnownGoodVersion ?? string.Empty,
            PendingTransaction = contentHealth?.PendingVersion ?? string.Empty,
            LastFailure = contentHealth?.LastFailure ?? string.Empty,
            LastResultKind = lastKind,
            LastMessage = lastMessage,
            Status = status,
        };
    }

    private SequenceDecision EvaluateSequence(string feedId, long sequence, string canonicalSha256)
    {
        var current = _stateStore.GetCurrent(feedId);
        if (!current.HasState) return SequenceDecision.Proceed;

        if (sequence < current.HighestSequence)
            return _policy.IsDowngradeOverrideActive ? SequenceDecision.Proceed : SequenceDecision.DowngradeRejected;

        if (sequence == current.HighestSequence)
        {
            return string.Equals(canonicalSha256, current.ManifestCanonicalSha256, StringComparison.OrdinalIgnoreCase)
                ? SequenceDecision.AlreadyCurrent
                : SequenceDecision.SequenceConflict;
        }

        return SequenceDecision.Proceed;
    }

    private UpdateApplyResult FailApply(UpdateResultKind kind, string message, string feedId, long sequence = 0)
    {
        Publish(kind, "Update rejected", message, UpdateEventFactory.SeverityFor(kind));
        RecordLast(kind, message);
        return UpdateApplyResult.Failure(kind, message, feedId, _stateStore.GetCurrent(feedId), sequence);
    }

    private void RecordLast(UpdateResultKind kind, string message)
    {
        lock (_gate)
        {
            _lastResultKind = kind;
            _lastMessage = message;
        }
    }

    private static bool IsDegraded(UpdateResultKind kind) => kind switch
    {
        UpdateResultKind.None => false,
        UpdateResultKind.Accepted => false,
        UpdateResultKind.Applied => false,
        UpdateResultKind.AlreadyCurrent => false,
        UpdateResultKind.RollbackCompleted => false,
        _ => true,
    };

    private void Publish(UpdateResultKind kind, string title, string description, RuntimeEventSeverity severity)
    {
        if (_eventPublisher is null) return;
        var runtimeEvent = UpdateEventFactory.Create(kind, _policy.FeedId, 0, title, description, severity);
        // Inline pipeline: deterministic, no background work.
        _eventPublisher.PublishAsync(runtimeEvent).GetAwaiter().GetResult();
    }
}
