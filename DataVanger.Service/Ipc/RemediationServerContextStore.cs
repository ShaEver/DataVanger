using System;
using System.Collections.Generic;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Policy;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Service.Ipc;

/// <summary>
/// Service-owned remediation context. It is registered from server-side
/// detection/remediation planning state and is the only source of threat band
/// and evidence flags used by the IPC execution handler.
/// </summary>
public sealed record RemediationServerContext
{
    public required RemediationCorrelationId CorrelationId { get; init; }
    public required RemediationTarget Target { get; init; }
    public required QuarantineThreatClassification ThreatBand { get; init; }
    public bool HasConfirmedEvidence { get; init; }
    public bool EvidenceIsHeuristicOnly { get; init; }
    public bool IsSystemFile { get; init; }

    public RemediationPolicyRequest ToPolicyRequest(RemediationActionKind action)
        => new()
        {
            CorrelationId = CorrelationId,
            Action = action,
            ThreatBand = ThreatBand,
            HasConfirmedEvidence = HasConfirmedEvidence,
            EvidenceIsHeuristicOnly = EvidenceIsHeuristicOnly,
            IsSystemFile = IsSystemFile,
        };
}

/// <summary>
/// In-memory service authority for remediation IPC. A client may name a
/// correlation id and target, but execution proceeds only when those values
/// match a context already registered by the service. Consent tokens are also
/// issued and retained here, so a serialized client token cannot authorize work.
/// </summary>
public sealed class RemediationServerContextStore
{
    private readonly object _sync = new();
    private readonly Dictionary<ContextKey, RemediationServerContext> _contexts = new();
    private readonly Dictionary<ConsentKey, RemediationConsentToken> _consents = new();

    public void Register(RemediationServerContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.CorrelationId.IsEmpty)
            throw new ArgumentException("Server remediation context requires a non-empty correlation id.", nameof(context));
        ArgumentNullException.ThrowIfNull(context.Target);

        lock (_sync)
        {
            _contexts[ContextKey.For(context.CorrelationId, context.Target)] = context;
        }
    }

    public bool TryResolve(
        RemediationCorrelationId correlationId,
        RemediationTarget target,
        out RemediationServerContext context)
    {
        ArgumentNullException.ThrowIfNull(target);
        lock (_sync)
        {
            return _contexts.TryGetValue(ContextKey.For(correlationId, target), out context!);
        }
    }

    public RemediationConsentToken IssueConsent(
        RemediationCorrelationId correlationId,
        RemediationActionKind action,
        RemediationTarget target,
        ConfirmationRequirement tier,
        DateTimeOffset nowUtc,
        TimeSpan ttl)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (!TryResolve(correlationId, target, out _))
            throw new InvalidOperationException("Cannot issue remediation consent without a matching server context.");

        var token = RemediationConsentToken.Issue(action, target.MatchKey, tier, correlationId, nowUtc, ttl);
        lock (_sync)
        {
            _consents[ConsentKey.For(correlationId, action, target)] = token;
        }

        return token;
    }

    public bool TryGetConsent(
        RemediationCorrelationId correlationId,
        RemediationActionKind action,
        RemediationTarget target,
        out RemediationConsentToken? consent)
    {
        ArgumentNullException.ThrowIfNull(target);
        lock (_sync)
        {
            if (_consents.TryGetValue(ConsentKey.For(correlationId, action, target), out var stored))
            {
                consent = stored;
                return true;
            }
        }

        consent = null;
        return false;
    }

    private readonly record struct ContextKey(RemediationCorrelationId CorrelationId, string TargetMatchKey)
    {
        public static ContextKey For(RemediationCorrelationId correlationId, RemediationTarget target)
            => new(correlationId, target.MatchKey);
    }

    private readonly record struct ConsentKey(
        RemediationCorrelationId CorrelationId,
        RemediationActionKind Action,
        string TargetMatchKey)
    {
        public static ConsentKey For(
            RemediationCorrelationId correlationId,
            RemediationActionKind action,
            RemediationTarget target)
            => new(correlationId, action, target.MatchKey);
    }
}
