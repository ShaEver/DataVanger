using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Ipc;

/// <summary>Kind of scan requested through the IPC boundary.</summary>
public enum ScanRequestKind
{
    Unknown = 0,
    Quick = 1,
    Custom = 2,
}

/// <summary>
/// Payload DTO for a scan request. Paths are validated by the service before
/// anything is queued. A scan request NEVER carries an executable command —
/// only declarative targets.
/// </summary>
public sealed class ScanRequestDto
{
    public ScanRequestKind Kind { get; init; } = ScanRequestKind.Quick;

    /// <summary>
    /// Target paths for a custom scan. Ignored for a quick scan. Bounded and
    /// validated (no traversal, no unsafe roots) by the service-side handler.
    /// </summary>
    public IReadOnlyList<string> Paths { get; init; } = Array.Empty<string>();
}

/// <summary>Payload DTO identifying a previously-started scan operation.</summary>
public sealed class ScanOperationRequestDto
{
    public string OperationId { get; init; } = string.Empty;
}

/// <summary>Bounded, UI-facing scan status DTO.</summary>
public sealed class ScanStatusDto
{
    public string OperationId { get; init; } = string.Empty;

    /// <summary>"Queued" | "Running" | "Completed" | "Cancelled" | "NotFound".</summary>
    public string State { get; init; } = "NotFound";

    public string Kind { get; init; } = "Quick";

    public string Message { get; init; } = string.Empty;
}
