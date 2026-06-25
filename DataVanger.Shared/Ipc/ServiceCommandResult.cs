using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Ipc;

/// <summary>
/// Payload DTO returned for command-style operations (pause/resume, scan
/// requests, quarantine actions, update checks). Carries an operation id when
/// the command starts a bounded asynchronous operation.
///
/// Anti-FP note: a command result is operational. It never carries or implies
/// a ConfirmedMalware verdict.
/// </summary>
public sealed class ServiceCommandResult
{
    public bool Success { get; init; }

    public string Message { get; init; } = string.Empty;

    /// <summary>Bounded-operation id (scan id, etc.), or null for synchronous commands.</summary>
    public string? OperationId { get; init; }

    /// <summary>Stable, machine-readable error token (null on success).</summary>
    public string? ErrorCode { get; init; }

    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

    public static ServiceCommandResult Ok(string message = "", string? operationId = null)
        => new() { Success = true, Message = message, OperationId = operationId };

    public static ServiceCommandResult Fail(string message, string errorCode)
        => new() { Success = false, Message = message, ErrorCode = errorCode };
}
