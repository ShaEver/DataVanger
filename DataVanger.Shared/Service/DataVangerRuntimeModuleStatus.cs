using System;

namespace DataVanger.Shared.Service;

/// <summary>
/// Honest, immutable status report for a single runtime module hosted by
/// the service runtime. Anti-false-positive rule: a non-Available module
/// (Passive / Disabled / Degraded / NotImplemented / Unavailable) MUST
/// never be reported as active protection and MUST never become
/// ConfirmedMalware evidence on its own.
/// </summary>
public sealed class DataVangerRuntimeModuleStatus
{
    public DataVangerRuntimeModuleStatus(
        string name,
        RuntimeModuleAvailability availability,
        string? detail = null)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Module name must be non-empty.", nameof(name));

        Name = name;
        Availability = availability;
        Detail = detail ?? string.Empty;
    }

    public string Name { get; }

    public RuntimeModuleAvailability Availability { get; }

    public string Detail { get; }

    /// <summary>
    /// True only when the module is fully Available. Any other availability
    /// label (Passive, Disabled, Degraded, NotImplemented, Unavailable)
    /// returns false — this is the gate the service status uses to refuse
    /// claiming "active protection".
    /// </summary>
    public bool IsActiveProtection
        => Availability == RuntimeModuleAvailability.Available
            && !Name.Equals("Configuration", StringComparison.OrdinalIgnoreCase);
}
