using System;

namespace DataVanger.Shared.Realtime;

/// <summary>
/// Result of a real-time scan as reported by the dispatcher / engine
/// integration layer. Carries the conservative verdict plus enough
/// context for the decision engine to choose an action.
///
/// Anti-FP guarantee: <see cref="IsConfirmedMalware"/> may only be true
/// when the underlying scan engine + classification policy produced a
/// ConfirmedMalware verdict (hash blacklist or confirmed signature).
/// Heuristic-only, behavioral-only, memory-only, ETW-only, browser-
/// extension-only, and reporting-only evidence MUST NEVER set this flag.
/// </summary>
public sealed class RealtimeScanResult
{
    public string Path { get; init; } = string.Empty;
    public RealtimeProtectionVerdict Verdict { get; init; } = RealtimeProtectionVerdict.Clean;

    /// <summary>
    /// Mirrors classification semantics. The decision engine treats
    /// IsConfirmedMalware=false as "never quarantine automatically".
    /// </summary>
    public bool IsConfirmedMalware { get; init; }

    /// <summary>
    /// True when the dispatcher served the result from the duplicate
    /// scan cache instead of invoking the engine.
    /// </summary>
    public bool FromCache { get; init; }

    /// <summary>
    /// True when the dispatcher could not produce a result (engine
    /// unavailable, cancellation, file vanished, etc.). The orchestrator
    /// surfaces this as a warning, never as a malware verdict.
    /// </summary>
    public bool Failed { get; init; }

    public string? FailureReason { get; init; }

    public DateTimeOffset CompletedAtUtc { get; init; }

    /// <summary>
    /// Optional message for the decision engine / status sink.
    /// </summary>
    public string? Message { get; init; }
}
