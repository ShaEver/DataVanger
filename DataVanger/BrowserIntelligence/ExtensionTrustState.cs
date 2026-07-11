namespace DataVanger.BrowserIntelligence;

/// <summary>
/// Trust state for a browser extension. Maps loosely to the broader
/// <see cref="DataVanger.Reputation.ReputationTrustState"/> but stays
/// specific to the extension-intelligence subsystem so the trust engine
/// can model nuances that don't apply to PE/script analysis.
///
/// Order matters: enum values are sorted from most trusted to most risky
/// so the trust engine can use plain comparisons.
/// </summary>
public enum ExtensionTrustState
{
    Trusted = 0,
    LikelyTrusted = 1,
    Unknown = 2,
    Suspicious = 3,
    HighRisk = 4,
    KnownMalicious = 5,
}
