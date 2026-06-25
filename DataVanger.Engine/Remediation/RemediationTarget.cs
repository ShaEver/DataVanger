using System;

namespace DataVanger.Engine.Remediation;

/// <summary>What kind of system object a remediation action targets. Used by the
/// plan validator to match a destructive Remove action to its preceding
/// containment action for the same object.</summary>
public enum RemediationTargetKind
{
    None = 0,
    File,
    Process,
    Service,
    RegistryValue,
    ScheduledTask,
    StartupEntry,
    BrowserExtension,
    SystemSetting,
}

/// <summary>
/// An immutable reference to the object an action targets. The identity is a
/// plain opaque string (path, PID, service name, registry value, …) — it is
/// NEVER dereferenced or touched in this phase; it exists only so plans can be
/// ordered and validated, and so the journal can record what an action was
/// about. Empty identity is invalid.
/// </summary>
public sealed record RemediationTarget
{
    public RemediationTarget(RemediationTargetKind kind, string identity)
    {
        if (kind == RemediationTargetKind.None)
            throw new ArgumentException("Remediation target kind must be specified.", nameof(kind));
        if (string.IsNullOrWhiteSpace(identity))
            throw new ArgumentException("Remediation target identity must be non-empty.", nameof(identity));

        Kind = kind;
        Identity = identity.Trim();
    }

    public RemediationTargetKind Kind { get; }

    /// <summary>Opaque identity (path/PID/name). Structural only; never touched.</summary>
    public string Identity { get; }

    /// <summary>Stable key used to match a Remove action to its containment.</summary>
    public string MatchKey => $"{Kind}:{Identity.ToLowerInvariant()}";

    public override string ToString() => MatchKey;
}
