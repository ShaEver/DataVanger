namespace DataVanger.Shared.Ipc;

/// <summary>Explicit protection-control action requested by the user.</summary>
public enum ProtectionControlAction
{
    Unknown = 0,
    PauseRealtime = 1,
    ResumeRealtime = 2,
}

/// <summary>
/// Payload DTO for an explicit, bounded protection-control command. Pausing or
/// resuming realtime protection is an intent expressed to the service; the
/// service remains authoritative and reports the honest resulting state.
/// </summary>
public sealed class ProtectionControlRequest
{
    public ProtectionControlAction Action { get; init; } = ProtectionControlAction.Unknown;

    /// <summary>Optional, short, user-facing reason for auditing. Never executed.</summary>
    public string Reason { get; init; } = string.Empty;
}

/// <summary>
/// Bounded, UI-facing protection status DTO. Anti-security-theater rule:
/// <see cref="HasActiveProtection"/> reflects the service's honest report and
/// is never fabricated.
/// </summary>
public sealed class ProtectionStatusDto
{
    /// <summary>Honest active-protection flag from the service runtime.</summary>
    public bool HasActiveProtection { get; init; }

    /// <summary>True when the user has requested realtime protection be paused.</summary>
    public bool RealtimePauseRequested { get; init; }

    /// <summary>Service lifecycle state name.</summary>
    public string State { get; init; } = "Unknown";

    public string Detail { get; init; } = string.Empty;
}
