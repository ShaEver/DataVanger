namespace DataVanger.Shared.Updates;

/// <summary>
/// Immutable record of the highest accepted update set for a feed. Used by the
/// state store for anti-downgrade enforcement and rollback.
/// </summary>
public sealed class UpdateStateSnapshot
{
    public string FeedId { get; init; } = string.Empty;

    /// <summary>Highest accepted manifest sequence. 0 means "no state yet".</summary>
    public long HighestSequence { get; init; }

    /// <summary>Lower-case hex SHA-256 of the accepted manifest's canonical payload.</summary>
    public string ManifestCanonicalSha256 { get; init; } = string.Empty;

    /// <summary>ISO-8601 UTC timestamp string when this state was recorded.</summary>
    public string AppliedUtc { get; init; } = string.Empty;

    /// <summary>True once at least one manifest has been accepted for the feed.</summary>
    public bool HasState => HighestSequence > 0;

    public static UpdateStateSnapshot Empty(string feedId) => new() { FeedId = feedId };
}
