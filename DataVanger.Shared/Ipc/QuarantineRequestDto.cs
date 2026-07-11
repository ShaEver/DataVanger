using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Ipc;

/// <summary>Quarantine operation requested through the IPC boundary.</summary>
public enum QuarantineOperation
{
    Unknown = 0,
    List = 1,
    Details = 2,
    Restore = 3,
    Delete = 4,
}

/// <summary>
/// Payload DTO for a quarantine command. Restore/Delete/Details require a
/// valid item id. Restore preserves all existing Secure Quarantine V2 safety:
/// the service refuses unsafe destinations, path traversal, and silent
/// overwrite — this DTO only expresses intent.
/// </summary>
public sealed class QuarantineRequestDto
{
    public QuarantineOperation Operation { get; init; } = QuarantineOperation.List;

    /// <summary>Quarantine item id. Required for Details/Restore/Delete.</summary>
    public string ItemId { get; init; } = string.Empty;

    /// <summary>Optional restore destination. Validated by the service.</summary>
    public string? DestinationPath { get; init; }

    /// <summary>Restore refuses to overwrite an existing file unless explicitly set.</summary>
    public bool AllowOverwrite { get; init; }
}

/// <summary>Bounded, UI-facing quarantine item summary DTO.</summary>
public sealed class QuarantineItemDto
{
    public string ItemId { get; init; } = string.Empty;
    public string OriginalPath { get; init; } = string.Empty;
    public string State { get; init; } = string.Empty;
    public DateTimeOffset QuarantinedUtc { get; init; }
    public string DetectionSummary { get; init; } = string.Empty;
}

/// <summary>Bounded list payload returned for <see cref="QuarantineOperation.List"/>.</summary>
public sealed class QuarantineListDto
{
    public IReadOnlyList<QuarantineItemDto> Items { get; init; } = Array.Empty<QuarantineItemDto>();
    public int TotalCount { get; init; }
}
