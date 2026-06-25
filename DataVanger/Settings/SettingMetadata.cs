namespace DataVanger.Settings;

/// <summary>
/// Plain-language grouping for the redesigned settings experience (Phase 06).
/// Behaviour-preserving metadata only — these categories organize the existing
/// <see cref="DataVanger.Core.AppSettings"/> without changing any stored value.
/// </summary>
public enum SettingGroup
{
    General = 0,
    Scanning,
    RealTimeProtection,
    ThreatRemoval,
    Quarantine,
    Updates,
    Privacy,
    AdvancedDiagnostics,
    DeveloperExperimental,
}

/// <summary>Reveal tiers. Normal hides Advanced and Developer; Advanced hides
/// only Developer; Developer reveals everything. Ordering is load-bearing for the
/// <c>(int)visibility &lt;= (int)revealLevel</c> filter.</summary>
public enum SettingVisibility
{
    Normal = 0,
    Advanced = 1,
    Developer = 2,
}

/// <summary>How risky a change is. <see cref="Protection"/> settings reduce
/// protection when disabled and therefore require confirm-on-disable; <see
/// cref="Safe"/> covers cosmetic/performance toggles that must not over-warn.</summary>
public enum SettingRisk
{
    Safe = 0,
    Caution,
    Protection,
}

/// <summary>The kind of control a setting maps to.</summary>
public enum SettingKind
{
    Toggle = 0,
    Number,
    Text,
    List,
}

/// <summary>
/// Descriptive metadata for one setting. It carries no value and mutates nothing;
/// it describes an existing <see cref="DataVanger.Core.AppSettings"/> field so the
/// UI can present it grouped, plain-language, reveal-gated, and (for protection
/// settings) confirm-on-disable.
/// </summary>
public sealed record SettingMetadata
{
    public required string Key { get; init; }
    public required string DisplayName { get; init; }
    public required string Description { get; init; }
    public required SettingGroup Group { get; init; }
    public required SettingKind Kind { get; init; }
    public SettingVisibility Visibility { get; init; } = SettingVisibility.Normal;
    public SettingRisk Risk { get; init; } = SettingRisk.Safe;

    /// <summary>True when turning this setting OFF must ask for confirmation.
    /// Only meaningful for protection-impacting toggles.</summary>
    public bool ConfirmOnDisable { get; init; }

    /// <summary>Unit/dimension hint for the value (e.g. "boolean", "score", "MB",
    /// "count", "url", "list"). Display-only.</summary>
    public string Dimension { get; init; } = string.Empty;
}
