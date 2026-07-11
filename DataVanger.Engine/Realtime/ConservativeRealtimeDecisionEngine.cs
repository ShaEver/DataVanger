using System;
using DataVanger.Shared.Realtime;

namespace DataVanger.Engine.Realtime;

/// <summary>
/// Conservative decision engine that strictly follows the existing
/// anti-false-positive policy:
///
///   - Failed scan          -> ObserveOnly, not authorized.
///   - Clean / Indeterminate -> ObserveOnly, not authorized.
///   - Suspicious           -> NotifyUser, not authorized.
///   - HighRisk             -> RecommendManualReview (+ deep scan),
///                             not authorized.
///   - ConfirmedMalware     -> QuarantineConfirmedMalware, but
///                             ActionAuthorized only when
///                             !PassiveMode AND
///                             AllowAutomaticQuarantineForConfirmedMalware.
/// </summary>
public sealed class ConservativeRealtimeDecisionEngine : IRealtimeProtectionDecisionEngine
{
    private readonly Func<DateTimeOffset> _utcNow;

    public ConservativeRealtimeDecisionEngine(Func<DateTimeOffset>? utcNow = null)
    {
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    public RealtimeProtectionDecision Decide(RealtimeScanResult scanResult, RealtimeProtectionOptions options)
    {
        if (scanResult is null) throw new ArgumentNullException(nameof(scanResult));
        if (options is null) throw new ArgumentNullException(nameof(options));

        if (scanResult.Failed)
        {
            return Build(scanResult, RealtimeProtectionAction.ObserveOnly,
                authorized: false,
                reason: scanResult.FailureReason ?? "scan failed; no malware verdict implied");
        }

        switch (scanResult.Verdict)
        {
            case RealtimeProtectionVerdict.ConfirmedMalware when scanResult.IsConfirmedMalware:
            {
                var allowAuto = options.AllowAutomaticQuarantineForConfirmedMalware && !options.PassiveMode;
                return Build(scanResult,
                    RealtimeProtectionAction.QuarantineConfirmedMalware,
                    authorized: allowAuto,
                    reason: allowAuto
                        ? "confirmed malware; automatic quarantine explicitly enabled"
                        : "confirmed malware; automatic quarantine NOT enabled (report only)");
            }

            case RealtimeProtectionVerdict.HighRisk:
                return Build(scanResult,
                    RealtimeProtectionAction.RecommendManualReview,
                    authorized: false,
                    reason: "heuristic high risk; manual review required (no auto-action allowed)");

            case RealtimeProtectionVerdict.Suspicious:
                return Build(scanResult,
                    RealtimeProtectionAction.NotifyUser,
                    authorized: false,
                    reason: "suspicious; observe and notify only");

            case RealtimeProtectionVerdict.Indeterminate:
                return Build(scanResult,
                    RealtimeProtectionAction.ObserveOnly,
                    authorized: false,
                    reason: "indeterminate verdict; no malware implied");

            case RealtimeProtectionVerdict.ConfirmedMalware:
                // Verdict claims ConfirmedMalware but IsConfirmedMalware
                // is false — anti-FP belt-and-braces: refuse to auto-act.
                return Build(scanResult,
                    RealtimeProtectionAction.RecommendManualReview,
                    authorized: false,
                    reason: "confirmed-malware verdict without confirmed flag; refusing automatic action");

            case RealtimeProtectionVerdict.Clean:
            default:
                return Build(scanResult,
                    RealtimeProtectionAction.ObserveOnly,
                    authorized: false,
                    reason: "clean");
        }
    }

    private RealtimeProtectionDecision Build(
        RealtimeScanResult scanResult,
        RealtimeProtectionAction action,
        bool authorized,
        string reason) => new()
    {
        Path = scanResult.Path,
        Verdict = scanResult.Verdict,
        RecommendedAction = action,
        ActionAuthorized = authorized,
        Reason = reason,
        DecidedAtUtc = _utcNow(),
    };
}
