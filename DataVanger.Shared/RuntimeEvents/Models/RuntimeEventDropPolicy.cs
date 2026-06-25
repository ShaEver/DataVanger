namespace DataVanger.Shared.RuntimeEvents;

/// <summary>
/// Policy for handling new events when the pipeline's bounded queue is
/// at capacity. The pipeline NEVER blocks indefinitely and NEVER throws
/// for overflow — it always increments the dropped counter and surfaces
/// a warning in the health snapshot.
/// </summary>
public enum RuntimeEventDropPolicy
{
    /// <summary>
    /// Drop the incoming event when the queue is full. Simplest,
    /// deterministic default; preserves existing in-flight events.
    /// </summary>
    DropNewest = 0,

    /// <summary>
    /// Prefer to drop low-severity informational events first when the
    /// queue is at capacity; otherwise behave like <see cref="DropNewest"/>.
    /// </summary>
    DropLowestSeverityFirst,
}
