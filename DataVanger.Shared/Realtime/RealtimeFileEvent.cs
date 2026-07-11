using System;

namespace DataVanger.Shared.Realtime;

/// <summary>
/// Normalized file system event emitted by the real-time protection
/// pipeline. The raw FileSystemWatcher / fake adapter notifications are
/// translated into this conservative model before reaching the
/// debouncer, queue, scan dispatcher or status sink.
///
/// Anti-FP note: a RealtimeFileEvent is telemetry only. It NEVER
/// classifies the file as malware on its own — that is the job of the
/// existing scan engine plus the existing classification policy.
/// </summary>
public sealed class RealtimeFileEvent
{
    public RealtimeFileEventKind Kind { get; init; }

    /// <summary>
    /// Normalized full path of the affected file. May be empty for
    /// watcher lifecycle / error events that have no path.
    /// </summary>
    public string Path { get; init; } = string.Empty;

    /// <summary>
    /// For Renamed events: the previous path before the rename.
    /// </summary>
    public string? OldPath { get; init; }

    public DateTimeOffset TimestampUtc { get; init; }

    /// <summary>
    /// Name of the watch profile that produced this event.
    /// </summary>
    public string SourceProfile { get; init; } = string.Empty;

    /// <summary>
    /// Optional human-readable reason — used for watcher errors,
    /// graceful-degradation warnings, and skip explanations.
    /// </summary>
    public string? Reason { get; init; }
}
