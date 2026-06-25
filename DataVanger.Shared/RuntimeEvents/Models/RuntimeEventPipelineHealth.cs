using System;
using System.Collections.Generic;

namespace DataVanger.Shared.RuntimeEvents;

/// <summary>
/// Diagnostic snapshot of the runtime event pipeline. Designed to be
/// consumed by future service IPC / UI status surfaces without leaking
/// implementation details.
/// </summary>
public sealed class RuntimeEventPipelineHealth
{
    public bool IsEnabled { get; init; }
    public bool IsDevelopmentMode { get; init; }
    public RuntimeEventPipelineMode Mode { get; init; }

    public int SubscriberCount { get; init; }

    public long EventsPublished { get; init; }
    public long EventsDelivered { get; init; }
    public long EventsDropped { get; init; }

    public int QueueDepth { get; init; }
    public int MaxQueueDepth { get; init; }
    public int MaxQueueSize { get; init; }

    /// <summary>
    /// One-line human-readable status (Disabled / Healthy / Degraded /
    /// Stopped). Never reports a malware verdict.
    /// </summary>
    public string Status { get; init; } = "Unknown";

    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}
