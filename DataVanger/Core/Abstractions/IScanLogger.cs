using System;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// Minimal logging contract used across the engine. Intentionally kept
/// separate from <c>Microsoft.Extensions.Logging</c> to avoid taking that
/// dependency in the Core layer; a thin adapter can be added later if needed.
///
/// Implementations MUST swallow their own failures — logging must never
/// crash a scan.
/// </summary>
public interface IScanLogger
{
    void Info(string message);
    void Warn(string message);
    void Error(string message, Exception? ex = null);

    /// <summary>Records that a single file was skipped, with a structured reason.</summary>
    void SkippedFile(string path, string reason);

    /// <summary>Records that a module failed on a file; used for resilience telemetry.</summary>
    void ModuleFailure(string moduleName, string path, Exception ex);
}
