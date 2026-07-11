using System;

namespace DataVanger.Shared.Realtime;

/// <summary>
/// Scan request flowing from the orchestrator's debouncer/queue to the
/// real-time scan dispatcher. The request carries enough metadata to
/// let the dispatcher (and downstream scan engine) make eligibility and
/// caching decisions without having to re-stat the file.
///
/// The orchestrator NEVER fabricates a SHA256 / size / timestamp — those
/// fields are populated only when the file stability probe was able to
/// observe the file safely. Missing values mean "unknown; fall back to
/// engine policy", never "trusted clean".
/// </summary>
public sealed class RealtimeScanRequest
{
    public string Path { get; init; } = string.Empty;
    public RealtimeFileEventKind TriggerKind { get; init; }
    public string SourceProfile { get; init; } = string.Empty;
    public DateTimeOffset EnqueuedAtUtc { get; init; }

    /// <summary>
    /// File length observed at stability time. -1 means "not observed".
    /// </summary>
    public long FileLength { get; init; } = -1;

    /// <summary>
    /// Last write timestamp observed at stability time. null means
    /// "not observed".
    /// </summary>
    public DateTimeOffset? LastWriteUtc { get; init; }

    /// <summary>
    /// SHA-256 hash, optional. The dispatcher may compute and cache it;
    /// callers should not assume it is present.
    /// </summary>
    public string? Sha256 { get; init; }
}
