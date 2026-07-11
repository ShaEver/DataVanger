namespace DataVanger.Shared.Realtime;

/// <summary>
/// Conservative verdict surface used by the real-time decision engine.
/// This mirrors the existing classification policy buckets without
/// taking a direct dependency on DataVanger.Core's ThreatClass — the
/// shared layer must remain independent of the WPF / engine internals.
///
/// Mapping (consumer-side):
///   Clean / Low risk      -> RealtimeProtectionVerdict.Clean
///   Suspect              -> RealtimeProtectionVerdict.Suspicious
///   HighRisk (heuristic) -> RealtimeProtectionVerdict.HighRisk
///   ConfirmedMalware     -> RealtimeProtectionVerdict.ConfirmedMalware
///
/// Anti-FP guarantee: ConfirmedMalware MUST originate from the existing
/// scan engine + classification policy. Real-time telemetry alone (a
/// file event, a suspicious extension, a locked file, a failed scan)
/// must NEVER become ConfirmedMalware via this enum.
/// </summary>
public enum RealtimeProtectionVerdict
{
    Clean,
    Suspicious,
    HighRisk,
    ConfirmedMalware,

    /// <summary>
    /// The scan engine could not produce a verdict (file vanished, was
    /// locked beyond the stability timeout, throttled, etc.). This is
    /// telemetry — NEVER malware.
    /// </summary>
    Indeterminate
}
