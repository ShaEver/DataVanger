using System.IO;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// Computes current file hashes. Implementations may persist bounded diagnostic
/// observations, but must never reuse them as a content-identity decision.
/// </summary>
public interface IHashService
{
    /// <summary>
    /// Returns the SHA-256 of the file in upper-case hex, or <c>null</c> on
    /// failure. <paramref name="cacheHit"/> is retained for compatibility and
    /// must be false for security-sensitive implementations.
    /// </summary>
    string? ComputeSha256(FileInfo file, out bool cacheHit);

    /// <summary>Persists bounded diagnostic observations; called once per scan.</summary>
    void Persist();

    /// <summary>Records diagnostic scan metadata; it must not affect decisions.</summary>
    void TouchScore(string fullPath, int lastScore, bool knownSafe);
}
