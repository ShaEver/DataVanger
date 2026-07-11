using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.SelfProtection;

/// <summary>
/// Outcome of an integrity validation pass.
///
/// Carries three buckets: matched paths, mismatched paths (hash diverged
/// from baseline) and missing paths (baseline present, file absent on
/// disk). Callers consume this result to emit tamper events; the
/// validator itself never raises events.
/// </summary>
public sealed class IntegrityValidationResult
{
    public IntegrityValidationResult(
        IReadOnlyList<string> matched,
        IReadOnlyList<IntegrityMismatch> mismatched,
        IReadOnlyList<string> missing,
        IReadOnlyList<IntegrityFailure> failures)
    {
        Matched = matched ?? Array.Empty<string>();
        Mismatched = mismatched ?? Array.Empty<IntegrityMismatch>();
        Missing = missing ?? Array.Empty<string>();
        Failures = failures ?? Array.Empty<IntegrityFailure>();
    }

    public IReadOnlyList<string> Matched { get; }
    public IReadOnlyList<IntegrityMismatch> Mismatched { get; }
    public IReadOnlyList<string> Missing { get; }

    /// <summary>Files where hashing itself failed (I/O error, access denied, etc).</summary>
    public IReadOnlyList<IntegrityFailure> Failures { get; }

    public bool IsClean => Mismatched.Count == 0 && Missing.Count == 0;

    public int CheckedCount => Matched.Count + Mismatched.Count + Missing.Count + Failures.Count;

    public static IntegrityValidationResult Empty { get; } = new IntegrityValidationResult(
        Array.Empty<string>(),
        Array.Empty<IntegrityMismatch>(),
        Array.Empty<string>(),
        Array.Empty<IntegrityFailure>());
}

/// <summary>Path whose current hash does not match the baseline.</summary>
public sealed class IntegrityMismatch
{
    public IntegrityMismatch(string path, string expectedHash, string actualHash)
    {
        Path = path ?? "";
        ExpectedHash = expectedHash ?? "";
        ActualHash = actualHash ?? "";
    }
    public string Path { get; }
    public string ExpectedHash { get; }
    public string ActualHash { get; }
}

/// <summary>Path whose hash could not be computed (graceful degradation).</summary>
public sealed class IntegrityFailure
{
    public IntegrityFailure(string path, string reason)
    {
        Path = path ?? "";
        Reason = reason ?? "";
    }
    public string Path { get; }
    public string Reason { get; }
}
