using System;

namespace DataVanger.Shared.Realtime;

/// <summary>
/// Structured event emitted by the real-time protection pipeline for
/// logging, status, and reporting consumers. RealtimeProtectionEvent is
/// the single typed channel between the orchestrator and any sink —
/// callers do not need to subscribe to internal channels or threads.
/// </summary>
public enum RealtimeProtectionEventKind
{
    Started,
    Stopped,
    WatchProfileStarted,
    WatchProfileDegraded,
    WatcherError,
    FileSkipped,
    ScanRequested,
    ScanCompleted,
    ScanFailed,
    DuplicateSuppressed,
    QueueOverflow,
    Warning,
    DecisionMade
}

public sealed class RealtimeProtectionEvent
{
    public RealtimeProtectionEventKind Kind { get; init; }
    public string? Path { get; init; }
    public string? Profile { get; init; }
    public string? Message { get; init; }
    public RealtimeProtectionVerdict? Verdict { get; init; }
    public RealtimeProtectionAction? Action { get; init; }
    public bool? ActionAuthorized { get; init; }
    public DateTimeOffset TimestampUtc { get; init; }
}
