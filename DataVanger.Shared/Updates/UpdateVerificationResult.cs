namespace DataVanger.Shared.Updates;

/// <summary>
/// Structured result of verifying (and downgrade-checking) a manifest.
///
/// Anti-FP guarantee: <see cref="IsConfirmedMalware"/> is a hard-coded
/// constant <c>false</c>. A failed/invalid/tampered/downgrade manifest is an
/// operational result, never a malware verdict.
/// </summary>
public sealed class UpdateVerificationResult
{
    public bool IsValid { get; init; }

    public UpdateResultKind Kind { get; init; } = UpdateResultKind.None;

    public string Message { get; init; } = string.Empty;

    public string FeedId { get; init; } = string.Empty;

    public long Sequence { get; init; }

    /// <summary>Lower-case hex SHA-256 of the canonical payload, when computed.</summary>
    public string? CanonicalSha256 { get; init; }

    /// <summary>Always false. Update telemetry is never a malware verdict.</summary>
    public bool IsConfirmedMalware => false;

    public static UpdateVerificationResult Valid(string feedId, long sequence, string canonicalSha256, UpdateResultKind kind = UpdateResultKind.Accepted, string message = "")
        => new()
        {
            IsValid = true,
            Kind = kind,
            Message = message,
            FeedId = feedId,
            Sequence = sequence,
            CanonicalSha256 = canonicalSha256,
        };

    public static UpdateVerificationResult Invalid(UpdateResultKind kind, string message, string feedId = "", long sequence = 0, string? canonicalSha256 = null)
        => new()
        {
            IsValid = false,
            Kind = kind,
            Message = message,
            FeedId = feedId,
            Sequence = sequence,
            CanonicalSha256 = canonicalSha256,
        };
}
