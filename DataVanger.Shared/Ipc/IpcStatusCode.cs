namespace DataVanger.Shared.Ipc;

/// <summary>
/// Structured, transport-neutral status code carried by every
/// <see cref="DataVangerResponse"/>. Mirrors the small set of outcomes the
/// IPC boundary must represent honestly so the UI never has to parse free
/// text to decide what happened.
///
/// Anti-FP note: none of these codes is a malware verdict. A failure is an
/// operational outcome, never ConfirmedMalware.
/// </summary>
public enum IpcStatusCode
{
    /// <summary>The command was handled successfully.</summary>
    Ok = 0,

    /// <summary>The request envelope or payload failed validation.</summary>
    BadRequest = 1,

    /// <summary>The command type is not on the allowlist.</summary>
    UnknownCommand = 2,

    /// <summary>The command is recognized but not supported in this host.</summary>
    Unsupported = 3,

    /// <summary>The service could not be reached (not installed / not running).</summary>
    ServiceUnavailable = 4,

    /// <summary>The request exceeded the bounded message size.</summary>
    PayloadTooLarge = 5,

    /// <summary>The request timed out before a response was produced.</summary>
    Timeout = 6,

    /// <summary>The request was cancelled by the caller.</summary>
    Cancelled = 7,

    /// <summary>A handler raised an unexpected exception (captured, not crashed).</summary>
    InternalError = 8,

    /// <summary>The service is reachable but running in a degraded state.</summary>
    Degraded = 9,
}
