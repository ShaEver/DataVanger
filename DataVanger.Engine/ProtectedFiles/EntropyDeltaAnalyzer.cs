using System;

namespace DataVanger.Engine.ProtectedFiles;

/// <summary>
/// Bounded, safe entropy helper for the Protected Files Activity Monitor
/// (Phase 2 / Step 07).
///
/// SAFETY CONTRACT:
///   - This analyzer NEVER reads files from disk. It operates only on a
///     bounded byte sample supplied by the caller, or on pre-computed
///     entropy values supplied via event metadata.
///   - Entropy is bounded to the configured sample size; oversized
///     samples are truncated, never fully buffered beyond the cap.
///   - Entropy is a WEAK signal. A high entropy value alone is NEVER
///     ConfirmedMalware and, on its own, does not even reach the
///     suspicious threshold in the scoring policy.
/// </summary>
public static class EntropyDeltaAnalyzer
{
    /// <summary>Entropy (bits/byte) at/above which content is considered high-entropy.</summary>
    public const double HighEntropyThreshold = 7.5;

    /// <summary>Minimum entropy increase (after-before) considered a meaningful delta.</summary>
    public const double SignificantDelta = 1.5;

    /// <summary>
    /// Computes Shannon entropy (bits/byte, 0..8) over a bounded prefix of
    /// the sample. Never throws. Returns 0 for empty input.
    /// </summary>
    public static double ComputeShannonEntropy(ReadOnlySpan<byte> sample, long maxBytes = 64 * 1024)
    {
        if (sample.Length == 0) return 0d;
        var limit = maxBytes <= 0 ? sample.Length : (int)Math.Min(sample.Length, maxBytes);
        if (limit <= 0) return 0d;

        Span<int> counts = stackalloc int[256];
        for (int i = 0; i < limit; i++)
        {
            counts[sample[i]]++;
        }

        double entropy = 0d;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            double p = (double)counts[i] / limit;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    /// <summary>True when the entropy value indicates high-entropy content.</summary>
    public static bool IsHighEntropy(double entropy) => entropy >= HighEntropyThreshold;

    /// <summary>
    /// Evaluates a before/after entropy pair (either may be null). Returns
    /// whether the data looks like a meaningful, ransomware-consistent
    /// entropy increase. Conservative: requires the "after" value to be
    /// high-entropy.
    /// </summary>
    public static bool IsSuspiciousIncrease(double? entropyBefore, double? entropyAfter)
    {
        if (entropyAfter is not double after) return false;
        if (!IsHighEntropy(after)) return false;
        if (entropyBefore is double before)
        {
            return (after - before) >= SignificantDelta;
        }
        // Only the "after" value is known; a single high-entropy reading is
        // a weak signal but acceptable to surface as a contributing reason.
        return true;
    }
}
