using System;

namespace DataVanger.Engine.Remediation.Policy;

/// <summary>
/// A consent token that binds a user's approval to an EXACT action + target +
/// confirmation tier, with an expiry and correlation id. A token for one action or
/// target can never authorize another, and an expired token authorizes nothing.
/// Issued only after the UI/service obtains the required confirmation.
/// </summary>
public sealed record RemediationConsentToken
{
    public required RemediationActionKind Action { get; init; }
    public required string TargetMatchKey { get; init; }
    public required ConfirmationRequirement Tier { get; init; }
    public required RemediationCorrelationId CorrelationId { get; init; }
    public required DateTimeOffset IssuedUtc { get; init; }
    public required DateTimeOffset ExpiresUtc { get; init; }

    public bool IsExpired(DateTimeOffset nowUtc) => nowUtc >= ExpiresUtc;

    public static RemediationConsentToken Issue(
        RemediationActionKind action, string targetMatchKey, ConfirmationRequirement tier,
        RemediationCorrelationId correlationId, DateTimeOffset nowUtc, TimeSpan ttl)
    {
        if (string.IsNullOrWhiteSpace(targetMatchKey))
            throw new ArgumentException("Target match key required.", nameof(targetMatchKey));
        if (correlationId.IsEmpty)
            throw new ArgumentException("Correlation id required.", nameof(correlationId));
        if (tier is ConfirmationRequirement.Unspecified or ConfirmationRequirement.None)
            throw new ArgumentException("A consent token must carry a real confirmation tier.", nameof(tier));
        if (ttl <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(ttl), "Consent token TTL must be positive.");
        return new RemediationConsentToken
        {
            Action = action,
            TargetMatchKey = targetMatchKey,
            Tier = tier,
            CorrelationId = correlationId,
            IssuedUtc = nowUtc,
            ExpiresUtc = nowUtc + ttl,
        };
    }
}

/// <summary>The result of an authorization check at the execution boundary.</summary>
public enum RemediationAuthorization
{
    Authorized = 0,
    DeniedByPolicy,
    ConsentMissing,
    ConsentMismatch,
    ConsentExpired,
    ConsentTierInsufficient,
    ConsentTierMismatch,
}

/// <summary>
/// A gate-issued execution permit. The constructor is internal so callers outside
/// the engine cannot forge authorization; they must obtain it from
/// <see cref="RemediationExecutionGate.Authorize"/>.
/// </summary>
public sealed class RemediationExecutionPermit
{
    internal RemediationExecutionPermit(
        RemediationActionKind action,
        string targetMatchKey,
        RemediationCorrelationId correlationId,
        RemediationPolicyDecision decision,
        DateTimeOffset authorizedUtc)
    {
        Action = action;
        TargetMatchKey = targetMatchKey;
        CorrelationId = correlationId;
        Decision = decision;
        AuthorizedUtc = authorizedUtc;
    }

    public RemediationActionKind Action { get; }
    public string TargetMatchKey { get; }
    public RemediationCorrelationId CorrelationId { get; }
    public RemediationPolicyDecision Decision { get; }
    public DateTimeOffset AuthorizedUtc { get; }
}

/// <summary>Full authorization outcome: the verdict, the policy decision, and a reason.</summary>
public sealed record RemediationAuthorizationResult
{
    public required RemediationAuthorization Authorization { get; init; }
    public required RemediationPolicyDecision Decision { get; init; }
    public RemediationExecutionPermit? Permit { get; init; }
    public string Reason { get; init; } = string.Empty;

    public bool IsAuthorized => Authorization == RemediationAuthorization.Authorized;
}

/// <summary>
/// The MANDATORY enforcement chokepoint between a remediation request and the
/// executor. Any service/IPC handler must call <see cref="Authorize"/> and proceed
/// ONLY when the result is authorized — a UI that sends an unsafe or unconsented
/// request is rejected here, regardless of what it asked for. The gate:
///   1. evaluates the policy (the single authority);
///   2. denies anything not Allowed (ReportOnly / NoAction / Blocked);
///   3. authorizes Allowed+automatic actions without consent;
///   4. for Allowed+consent actions, requires a non-expired consent token that binds
///      the EXACT action + target and carries a tier at least as strong as required.
/// It fails closed on any mismatch.
/// </summary>
public sealed class RemediationExecutionGate
{
    private readonly RemediationPolicy _policy;

    public RemediationExecutionGate(RemediationPolicy? policy = null)
        => _policy = policy ?? RemediationPolicy.Instance;

    public RemediationAuthorizationResult Authorize(
        RemediationPolicyRequest request,
        string targetMatchKey,
        RemediationConsentToken? consent,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(targetMatchKey))
            throw new ArgumentException("Target match key required.", nameof(targetMatchKey));

        var decision = _policy.Evaluate(request);

        if (decision.Outcome != PolicyOutcome.Allowed)
            return Result(RemediationAuthorization.DeniedByPolicy, decision,
                $"Policy did not allow the action ({decision.Outcome}: {decision.DenialReason}).");

        if (request.CorrelationId.IsEmpty)
            return Result(RemediationAuthorization.ConsentMismatch, decision, "A non-empty correlation id is required.");

        if (decision.IsAutomatic)
            return Result(
                RemediationAuthorization.Authorized,
                decision,
                "Allowed automatically (safe, reversible, confirmed).",
                Permit(request, targetMatchKey, decision, nowUtc));

        // Consent required from here on.
        if (consent is null)
            return Result(RemediationAuthorization.ConsentMissing, decision, "A consent token is required but none was provided.");

        if (consent.Action != request.Action ||
            !string.Equals(consent.TargetMatchKey, targetMatchKey, StringComparison.OrdinalIgnoreCase) ||
            consent.CorrelationId != request.CorrelationId)
            return Result(RemediationAuthorization.ConsentMismatch, decision, "Consent token does not bind this exact action + target + correlation.");

        if (consent.IsExpired(nowUtc))
            return Result(RemediationAuthorization.ConsentExpired, decision, "Consent token has expired.");

        if (TierStrength(consent.Tier) < TierStrength(decision.RequiredConfirmation))
            return Result(RemediationAuthorization.ConsentTierInsufficient, decision,
                $"Consent tier '{consent.Tier}' is weaker than the required '{decision.RequiredConfirmation}'.");

        if (consent.Tier != decision.RequiredConfirmation)
            return Result(RemediationAuthorization.ConsentTierMismatch, decision,
                "Consent token does not bind this exact confirmation tier.");

        return Result(
            RemediationAuthorization.Authorized,
            decision,
            "Authorized with a matching, valid consent token.",
            Permit(request, targetMatchKey, decision, nowUtc));
    }

    private static int TierStrength(ConfirmationRequirement c) => c switch
    {
        ConfirmationRequirement.None => 0,
        ConfirmationRequirement.UserConfirmation => 1,
        ConfirmationRequirement.RebootConsent => 2,
        ConfirmationRequirement.AdvancedConfirmation => 3,
        _ => -1, // Unspecified
    };

    private static RemediationExecutionPermit Permit(
        RemediationPolicyRequest request,
        string targetMatchKey,
        RemediationPolicyDecision decision,
        DateTimeOffset nowUtc)
        => new(request.Action, targetMatchKey, request.CorrelationId, decision, nowUtc);

    private static RemediationAuthorizationResult Result(
        RemediationAuthorization auth,
        RemediationPolicyDecision decision,
        string reason,
        RemediationExecutionPermit? permit = null)
        => new() { Authorization = auth, Decision = decision, Reason = reason, Permit = permit };
}
