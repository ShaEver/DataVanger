namespace DataVanger.Shared.Updates;

/// <summary>
/// Recognized update package content kinds. Every kind in this phase is
/// passive, non-executable data (JSON feeds / rules text). Update package
/// code is NEVER loaded or executed in this phase.
/// </summary>
public enum UpdatePackageKind
{
    /// <summary>Unrecognized kind. Always rejected by package validation.</summary>
    Unknown = 0,
    HashBlacklist = 1,
    HashAllowlist = 2,
    ReputationMetadata = 3,
    YaraRules = 4,
    BrowserExtensionFeed = 5,
    Configuration = 6,
    ThreatMetadata = 7,
}
