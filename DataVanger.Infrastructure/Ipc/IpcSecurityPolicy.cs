using System;
using System.Collections.Generic;
using System.IO;
using DataVanger.Shared.Ipc;

namespace DataVanger.Infrastructure.Ipc;

/// <summary>Outcome of validating a request before routing.</summary>
public readonly struct IpcValidationResult
{
    private IpcValidationResult(bool isValid, IpcStatusCode statusCode, string message, string? errorCode)
    {
        IsValid = isValid;
        StatusCode = statusCode;
        Message = message;
        ErrorCode = errorCode;
    }

    public bool IsValid { get; }
    public IpcStatusCode StatusCode { get; }
    public string Message { get; }
    public string? ErrorCode { get; }

    public static IpcValidationResult Valid { get; } =
        new(true, IpcStatusCode.Ok, string.Empty, null);

    public static IpcValidationResult Invalid(IpcStatusCode statusCode, string message, string errorCode)
        => new(false, statusCode, message, errorCode);
}

/// <summary>
/// Central, structured validation for the IPC boundary. Enforces the command
/// allowlist, the bounded message size, and safe path rules. Pure and
/// deterministic — no I/O, no privilege checks, no admin assumptions.
/// </summary>
public static class IpcSecurityPolicy
{
    /// <summary>
    /// Validate a request envelope against the allowlist and size bound. Does
    /// NOT validate payload semantics — that is each handler's responsibility.
    /// </summary>
    public static IpcValidationResult ValidateRequest(DataVangerRequest? request, IpcOptions options)
    {
        if (request is null)
            return IpcValidationResult.Invalid(IpcStatusCode.BadRequest, "Request was null.", "NullRequest");

        if (!DataVangerCommandCatalog.IsAllowed(request.CommandType))
            return IpcValidationResult.Invalid(
                IpcStatusCode.UnknownCommand,
                $"Command '{request.CommandType}' is not on the allowlist.",
                "UnknownCommand");

        int payloadBytes = IpcSerialization.ByteSize(request.PayloadJson);
        if (payloadBytes > options.MaxMessageBytes)
            return IpcValidationResult.Invalid(
                IpcStatusCode.PayloadTooLarge,
                $"Request payload ({payloadBytes} bytes) exceeds the bounded limit ({options.MaxMessageBytes} bytes).",
                "PayloadTooLarge");

        return IpcValidationResult.Valid;
    }

    /// <summary>True when a single scan/restore path is well-formed and safe.</summary>
    public static bool IsSafePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;

        // Reject obvious traversal and UNC/remote forms. Local desktop scans
        // only; the service is the authority for deeper policy.
        if (path.Contains("..", StringComparison.Ordinal)) return false;
        if (path.StartsWith(@"\\", StringComparison.Ordinal)) return false;

        if (path.IndexOfAny(Path.GetInvalidPathChars()) >= 0) return false;

        try
        {
            // Path.GetFullPath throws on malformed input; we only use it as a
            // structural validity probe (no file is touched).
            _ = Path.GetFullPath(path);
        }
        catch
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Validate a set of scan paths. Returns false and the offending entry when
    /// any path is unsafe. An empty list is invalid for a custom scan.
    /// </summary>
    public static bool TryValidateScanPaths(IReadOnlyList<string> paths, out string rejectedPath)
    {
        rejectedPath = string.Empty;
        if (paths is null || paths.Count == 0)
        {
            rejectedPath = "(none)";
            return false;
        }

        for (int i = 0; i < paths.Count; i++)
        {
            if (!IsSafePath(paths[i]))
            {
                rejectedPath = paths[i] ?? "(null)";
                return false;
            }
        }

        return true;
    }
}
