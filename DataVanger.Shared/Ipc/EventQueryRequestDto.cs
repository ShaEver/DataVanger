using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Ipc;

/// <summary>
/// Payload DTO for a bounded event/history query. The query is always bounded:
/// the service clamps <see cref="Limit"/> to a hard maximum and never returns
/// unbounded history.
/// </summary>
public sealed class EventQueryRequestDto
{
    /// <summary>Hard upper bound the service enforces regardless of request.</summary>
    public const int MaxLimit = 200;

    public const int DefaultLimit = 50;

    private readonly int _limit = DefaultLimit;

    /// <summary>
    /// Requested maximum number of events. Values below 1 fall back to the
    /// default; values above <see cref="MaxLimit"/> are clamped by the service.
    /// </summary>
    public int Limit
    {
        get => _limit;
        init => _limit = value < 1 ? DefaultLimit : value;
    }

    /// <summary>Number of most-recent events to skip (pagination). Never negative.</summary>
    public int Offset { get; init; }

    /// <summary>Optional minimum severity name filter (e.g. "Medium"). Empty = all.</summary>
    public string MinimumSeverity { get; init; } = string.Empty;
}

/// <summary>
/// Bounded, UI-facing security-event DTO. A flattened, safe projection of a
/// runtime security event. Anti-FP note: <see cref="Classification"/> is a
/// telemetry label, never a ConfirmedMalware verdict.
/// </summary>
public sealed class SecurityEventDto
{
    public string EventId { get; init; } = string.Empty;
    public DateTimeOffset TimestampUtc { get; init; }
    public string Source { get; init; } = string.Empty;
    public string Severity { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Summary { get; init; } = string.Empty;
    public string CorrelationId { get; init; } = string.Empty;
    public string ActionTaken { get; init; } = string.Empty;

    /// <summary>Telemetry classification label only — never ConfirmedMalware.</summary>
    public string Classification { get; init; } = "Telemetry";
}

/// <summary>Bounded result payload for an event query.</summary>
public sealed class EventQueryResultDto
{
    public IReadOnlyList<SecurityEventDto> Events { get; init; } = Array.Empty<SecurityEventDto>();

    /// <summary>Total events available before limit/offset were applied.</summary>
    public int TotalAvailable { get; init; }

    /// <summary>The effective limit the service applied (after clamping).</summary>
    public int AppliedLimit { get; init; }
}
