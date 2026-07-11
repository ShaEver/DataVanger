namespace DataVanger.Scheduling.Models;

/// <summary>
/// Decides what happens when the scheduler discovers that a scheduled
/// run was missed (machine was off, scheduler paused, ...).
/// </summary>
public enum MissedRunPolicy
{
    /// <summary>Skip every missed occurrence and resume at the next future slot.</summary>
    Skip,

    /// <summary>Run a single catch-up execution, then resume normally.</summary>
    RunOnceCatchUp,
}
