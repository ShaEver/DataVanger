using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Etw;

/// <summary>
/// Diagnostic snapshot of an <see cref="DataVanger.Shared.Etw"/> runtime
/// provider. Designed to be safe to serialize to UI/IPC surfaces in
/// future phases without leaking implementation details.
///
/// Anti-FP guarantee:
///   No field on this DTO carries a classification verdict. It is
///   purely operational health — start time, counters, last error,
///   current status. ConfirmedMalware does not flow through this type.
/// </summary>
public sealed class EtwProviderHealth
{
    /// <summary>Friendly provider name (e.g. "null-etw", "in-memory-etw", "windows-etw").</summary>
    public string ProviderName { get; init; } = string.Empty;

    public EtwProviderStatus Status { get; init; } = EtwProviderStatus.Disabled;

    public DateTimeOffset? StartedAtUtc { get; init; }
    public DateTimeOffset? StoppedAtUtc { get; init; }

    /// <summary>Total normalized events that were successfully published to the runtime pipeline.</summary>
    public long EventsPublished { get; init; }

    /// <summary>Total events the provider observed but did not publish (rate limit, filter, queue full).</summary>
    public long EventsDropped { get; init; }

    /// <summary>Total events the provider tried to publish but the pipeline rejected/failed.</summary>
    public long EventsFailed { get; init; }

    /// <summary>Whether the running host even supports the ETW backend (Windows).</summary>
    public bool IsPlatformSupported { get; init; }

    /// <summary>Whether configuration explicitly allows the real provider.</summary>
    public bool IsRealProviderAllowed { get; init; }

    /// <summary>Whether the provider is currently in development-mode (real ETW off by default).</summary>
    public bool IsDevelopmentMode { get; init; }

    /// <summary>Compact human-readable last error, if any. Never contains stack traces or secrets.</summary>
    public string? LastError { get; init; }

    /// <summary>Operational warnings (bounded). Never carries malware verdicts.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}
