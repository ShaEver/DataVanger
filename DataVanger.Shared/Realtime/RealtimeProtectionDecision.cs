using System;

namespace DataVanger.Shared.Realtime;

/// <summary>
/// Decision produced by the conservative real-time decision engine.
/// Carries both the recommended <see cref="RealtimeProtectionAction"/>
/// and whether the action was actually authorized — which is gated by
/// PassiveMode and the explicit AllowAutomaticQuarantine setting.
/// </summary>
public sealed class RealtimeProtectionDecision
{
    public string Path { get; init; } = string.Empty;
    public RealtimeProtectionVerdict Verdict { get; init; }
    public RealtimeProtectionAction RecommendedAction { get; init; }

    /// <summary>
    /// True only when:
    ///   - Verdict == ConfirmedMalware, AND
    ///   - RecommendedAction == QuarantineConfirmedMalware, AND
    ///   - PassiveMode == false, AND
    ///   - AllowAutomaticQuarantineForConfirmedMalware == true.
    /// Otherwise false — the orchestrator must report-only.
    /// </summary>
    public bool ActionAuthorized { get; init; }

    public string? Reason { get; init; }

    public DateTimeOffset DecidedAtUtc { get; init; }
}
