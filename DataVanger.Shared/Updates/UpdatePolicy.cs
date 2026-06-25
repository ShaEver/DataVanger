using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Updates;

/// <summary>
/// Options governing the signed-update subsystem. Pure options DTO with safe
/// defaults: signed manifests are ALWAYS required, downgrade override is OFF,
/// and the default mode is the deterministic, network-free <see cref="UpdateMode.Test"/>.
/// </summary>
public sealed class UpdatePolicy
{
    private static readonly IReadOnlyList<UpdatePackageKind> DefaultAllowedKinds = new[]
    {
        UpdatePackageKind.HashBlacklist,
        UpdatePackageKind.HashAllowlist,
        UpdatePackageKind.ReputationMetadata,
        UpdatePackageKind.YaraRules,
        UpdatePackageKind.BrowserExtensionFeed,
        UpdatePackageKind.Configuration,
        UpdatePackageKind.ThreatMetadata,
    };

    public UpdateMode Mode { get; init; } = UpdateMode.Test;

    public string FeedId { get; init; } = "datavanger-default-feed";

    /// <summary>Maximum allowed size of any single package's content.</summary>
    public long MaxPackageSizeBytes { get; init; } = 16L * 1024 * 1024;

    /// <summary>
    /// Forced-downgrade override. DISABLED by default. Even when true it is
    /// honored ONLY in <see cref="UpdateMode.Development"/> or
    /// <see cref="UpdateMode.Test"/> (see <see cref="IsDowngradeOverrideActive"/>).
    /// </summary>
    public bool AllowDowngradeInDevelopmentMode { get; init; }

    public IReadOnlyList<UpdatePackageKind> AllowedKinds { get; init; } = DefaultAllowedKinds;

    /// <summary>Whether any update activity is permitted.</summary>
    public bool IsUpdatingEnabled => Mode != UpdateMode.Disabled;

    /// <summary>
    /// Signed manifests are always required in this design. There is no
    /// trust-on-first-use and no unsigned acceptance path.
    /// </summary>
    public bool RequiresSignature => true;

    /// <summary>True only for the development/test modes.</summary>
    public bool IsDevelopmentOrTestMode => Mode is UpdateMode.Development or UpdateMode.Test;

    /// <summary>
    /// True only when a downgrade should actually be permitted: the override
    /// flag is set AND the mode is Development/Test. Production-like modes can
    /// never downgrade regardless of the flag.
    /// </summary>
    public bool IsDowngradeOverrideActive =>
        AllowDowngradeInDevelopmentMode && IsDevelopmentOrTestMode;

    public bool IsKindAllowed(UpdatePackageKind kind)
    {
        if (kind == UpdatePackageKind.Unknown) return false;
        foreach (var allowed in AllowedKinds)
            if (allowed == kind) return true;
        return false;
    }

    /// <summary>Deterministic, network-free defaults for tests.</summary>
    public static UpdatePolicy TestDefault() => new() { Mode = UpdateMode.Test };

    /// <summary>Production-like defaults: auto-apply signed feeds only.</summary>
    public static UpdatePolicy ProductionDefault() => new() { Mode = UpdateMode.AutoApplyFeedsOnly };
}
