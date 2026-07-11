using DataVanger.Shared.Realtime;

namespace DataVanger.Engine.Realtime;

/// <summary>
/// Maps a <see cref="RealtimeScanResult"/> to a
/// <see cref="RealtimeProtectionDecision"/>. The decision engine is the
/// single place that consults PassiveMode and the explicit
/// AllowAutomaticQuarantineForConfirmedMalware setting — orchestrators
/// MUST NOT bypass it.
///
/// Anti-FP contract:
///   - Only ConfirmedMalware verdicts may yield
///     <see cref="RealtimeProtectionAction.QuarantineConfirmedMalware"/>.
///   - PassiveMode forces ActionAuthorized=false for every destructive
///     action regardless of verdict.
///   - When AllowAutomaticQuarantineForConfirmedMalware=false,
///     ActionAuthorized=false even for ConfirmedMalware (the recommended
///     action is still surfaced, but the orchestrator only reports).
/// </summary>
public interface IRealtimeProtectionDecisionEngine
{
    RealtimeProtectionDecision Decide(RealtimeScanResult scanResult, RealtimeProtectionOptions options);
}
