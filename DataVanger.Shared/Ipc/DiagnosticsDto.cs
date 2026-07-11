using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Ipc;

/// <summary>
/// Payload DTO requesting a diagnostic bundle. The bundle is a bounded,
/// read-only summary of health/status text — it NEVER executes commands,
/// collects arbitrary files, or runs a shell.
/// </summary>
public sealed class DiagnosticsRequestDto
{
    /// <summary>When true, include the module status list in the bundle.</summary>
    public bool IncludeModules { get; init; } = true;

    /// <summary>When true, include update health in the bundle.</summary>
    public bool IncludeUpdateHealth { get; init; } = true;
}

/// <summary>Bounded, UI-facing diagnostic bundle DTO.</summary>
public sealed class DiagnosticsBundleDto
{
    public DateTimeOffset GeneratedUtc { get; init; } = DateTimeOffset.UtcNow;

    public string HostKind { get; init; } = string.Empty;

    public string ServiceState { get; init; } = string.Empty;

    public IReadOnlyList<string> Lines { get; init; } = Array.Empty<string>();
}
