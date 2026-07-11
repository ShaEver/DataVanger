namespace DataVanger.Shared.Realtime;

/// <summary>
/// Conservative response actions for real-time protection. The decision
/// engine MAY recommend any of these; the orchestrator only executes
/// the destructive ones (QuarantineConfirmedMalware) when:
///   1. the verdict is ConfirmedMalware, AND
///   2. RealtimeProtectionOptions.AllowAutomaticQuarantineForConfirmedMalware
///      is explicitly true, AND
///   3. the orchestrator is NOT in PassiveMode.
/// </summary>
public enum RealtimeProtectionAction
{
    None,
    ObserveOnly,
    NotifyUser,
    RecommendManualReview,
    RequestDeepScan,
    QuarantineConfirmedMalware
}
