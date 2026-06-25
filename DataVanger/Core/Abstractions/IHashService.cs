using System.IO;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// Computes and caches file hashes. Implementations are expected to be
/// thread-safe and to reuse cached values when the file's length and write
/// timestamp are unchanged.
/// </summary>
public interface IHashService
{
    /// <summary>
    /// Returns the SHA-256 of the file in upper-case hex, or <c>null</c> on
    /// failure. <paramref name="cacheHit"/> indicates whether the result came
    /// from the cache (used for telemetry).
    /// </summary>
    string? ComputeSha256(FileInfo file, out bool cacheHit);

    /// <summary>Persists the cache to disk; called once per scan.</summary>
    void Persist();

    /// <summary>Records the last observed score for cache pruning decisions.</summary>
    void TouchScore(string fullPath, int lastScore, bool knownSafe);
}
