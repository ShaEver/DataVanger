using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Ipc;

/// <summary>
/// Bounded, UI-facing status snapshot DTO. This is a flattened, string-based
/// projection of the service runtime status — it deliberately does NOT expose
/// internal runtime objects. Built by the service-side status handler and
/// consumed by the UI for display.
/// </summary>
public sealed class ServiceStatusSnapshot
{
    /// <summary>Service lifecycle state name (e.g. "Running", "Degraded", "Stopped").</summary>
    public string State { get; init; } = "Unknown";

    /// <summary>Runtime mode name (e.g. "Development", "Console", "Service").</summary>
    public string Mode { get; init; } = "Development";

    /// <summary>
    /// Honest active-protection flag. Mirrors the runtime's own honest gate:
    /// false unless at least one module is genuinely Available AND the runtime
    /// is Running. Never fabricated by the UI.
    /// </summary>
    public bool HasActiveProtection { get; init; }

    public DateTimeOffset LastUpdatedUtc { get; init; }

    public DateTimeOffset? StartedAtUtc { get; init; }

    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

    public IReadOnlyList<ModuleStatusDto> Modules { get; init; } = Array.Empty<ModuleStatusDto>();
}

/// <summary>
/// Bounded module status DTO for UI consumption. A flattened projection of a
/// single runtime module's honest availability.
/// </summary>
public sealed class ModuleStatusDto
{
    public string Name { get; init; } = string.Empty;

    /// <summary>Availability label (e.g. "Available", "Passive", "NotImplemented").</summary>
    public string Availability { get; init; } = "Unavailable";

    public string Detail { get; init; } = string.Empty;

    /// <summary>True only when the module is genuinely active protection.</summary>
    public bool IsActiveProtection { get; init; }
}

/// <summary>Bounded module-list payload returned for GetModuleStatus.</summary>
public sealed class ModuleStatusListDto
{
    public IReadOnlyList<ModuleStatusDto> Modules { get; init; } = Array.Empty<ModuleStatusDto>();

    public int Count => Modules.Count;
}

/// <summary>Bounded configuration-summary payload returned for GetConfigurationSummary.</summary>
public sealed class ConfigurationSummaryDto
{
    public string Mode { get; init; } = string.Empty;

    /// <summary>Short, non-sensitive summary lines for display.</summary>
    public IReadOnlyList<string> Lines { get; init; } = Array.Empty<string>();
}
