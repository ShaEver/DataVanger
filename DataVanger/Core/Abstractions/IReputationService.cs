using DataVanger.Core;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// Local file-reputation store. Tracks first/last-seen timestamps, last score
/// and user decisions for hashes encountered by previous scans.
///
/// A future cloud reputation adapter can implement this same interface
/// (<c>CloudReputationService</c>) and be plugged in via the registry.
/// </summary>
public interface IReputationService
{
    /// <summary>Returns the stored entry for the hash, or null if unknown.</summary>
    object? Lookup(string sha256);

    /// <summary>Records what was observed about the finding during this scan.</summary>
    void Observe(ScanFinding finding);

    /// <summary>Flushes pending changes to disk.</summary>
    void Persist();
}
