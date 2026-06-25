namespace DataVanger.Shared.Updates;

/// <summary>
/// Cheap, read-only health/status view of the signed-update subsystem for
/// reporting and UI surfacing. Never throws and never carries a verdict.
/// </summary>
public sealed class UpdateHealthSnapshot
{
    public bool IsEnabled { get; init; }

    public UpdateMode Mode { get; init; } = UpdateMode.Disabled;

    public string FeedId { get; init; } = string.Empty;

    public long HighestSequence { get; init; }

    public bool HasLastKnownGood { get; init; }

    /// <summary>Outcome kind of the most recent operation, if any.</summary>
    public UpdateResultKind LastResultKind { get; init; } = UpdateResultKind.None;

    public string LastMessage { get; init; } = string.Empty;

    /// <summary>"Disabled" | "Healthy" | "Degraded".</summary>
    public string Status { get; init; } = "Disabled";

    /// <summary>Always false. Update health is operational, never a verdict.</summary>
    public bool IsConfirmedMalware => false;
}
