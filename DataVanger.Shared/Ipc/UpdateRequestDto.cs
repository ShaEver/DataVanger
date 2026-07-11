namespace DataVanger.Shared.Ipc;

/// <summary>Update operation requested through the IPC boundary.</summary>
public enum UpdateOperation
{
    Unknown = 0,
    CheckForUpdates = 1,
    GetStatus = 2,
}

/// <summary>
/// Payload DTO for an update command. The IPC layer never changes
/// update-signature logic; it only triggers a bounded check or reads the
/// current honest update health.
/// </summary>
public sealed class UpdateRequestDto
{
    public UpdateOperation Operation { get; init; } = UpdateOperation.GetStatus;
}

/// <summary>Bounded, UI-facing update status DTO. Never carries a verdict.</summary>
public sealed class UpdateStatusDto
{
    public bool IsEnabled { get; init; }

    /// <summary>"Disabled" | "Healthy" | "Degraded".</summary>
    public string Status { get; init; } = "Disabled";

    public string FeedId { get; init; } = string.Empty;

    public long HighestSequence { get; init; }

    public bool HasLastKnownGood { get; init; }

    public string LastMessage { get; init; } = string.Empty;
}
