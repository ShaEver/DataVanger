using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Ipc;

/// <summary>
/// Immutable response envelope returned by the service to the UI. Failures are
/// represented here as structured data — the IPC boundary never throws across
/// the wire and never crashes the UI.
/// </summary>
public sealed class DataVangerResponse
{
    public string RequestId { get; init; } = string.Empty;

    public bool Success { get; init; }

    public IpcStatusCode StatusCode { get; init; } = IpcStatusCode.Ok;

    public string Message { get; init; } = string.Empty;

    public int PayloadVersion { get; init; } = 1;

    /// <summary>JSON of a concrete response DTO, or null when there is no payload.</summary>
    public string? PayloadJson { get; init; }

    /// <summary>Stable, machine-readable error token (null on success).</summary>
    public string? ErrorCode { get; init; }

    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

    public static DataVangerResponse Ok(
        string requestId,
        string? payloadJson = null,
        string message = "",
        int payloadVersion = 1,
        IReadOnlyList<string>? warnings = null)
        => new()
        {
            RequestId = requestId,
            Success = true,
            StatusCode = IpcStatusCode.Ok,
            Message = message,
            PayloadJson = payloadJson,
            PayloadVersion = payloadVersion,
            Warnings = warnings ?? Array.Empty<string>(),
        };

    public static DataVangerResponse Error(
        string requestId,
        IpcStatusCode statusCode,
        string message,
        string? errorCode = null,
        IReadOnlyList<string>? warnings = null)
        => new()
        {
            RequestId = requestId,
            Success = false,
            StatusCode = statusCode,
            Message = message ?? string.Empty,
            ErrorCode = errorCode ?? statusCode.ToString(),
            Warnings = warnings ?? Array.Empty<string>(),
        };
}
