namespace DataVanger.Core.Domain;

/// <summary>
/// Coarse trust classification of a file derived from hash, signature and path.
/// This is an INPUT to the classifier — never a verdict by itself.
/// </summary>
public enum FileTrustState
{
    /// <summary>No reputation information available yet.</summary>
    Unknown,

    /// <summary>Hash matches a known-good entry (vendor allowlist or user whitelist).</summary>
    KnownSafe,

    /// <summary>File is signed by a trusted publisher.</summary>
    TrustedPublisher,

    /// <summary>Hash matches a known-bad entry.</summary>
    KnownMalicious,

    /// <summary>File lives in a path the user explicitly excluded.</summary>
    Excluded,
}
