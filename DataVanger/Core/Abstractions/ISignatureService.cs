namespace DataVanger.Core.Abstractions;

/// <summary>
/// Local hash blacklist/whitelist lookup. Implementations load from disk on
/// construction and treat the data as read-only for the duration of a scan.
/// </summary>
public interface ISignatureService
{
    bool IsKnownMalicious(string sha256);
    bool IsKnownSafe(string sha256);

    /// <summary>Total number of hashes loaded across all databases.</summary>
    int TotalHashes { get; }
}
