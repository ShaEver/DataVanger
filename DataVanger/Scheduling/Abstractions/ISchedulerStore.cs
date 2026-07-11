using System.Collections.Generic;
using DataVanger.Scheduling.Models;

namespace DataVanger.Scheduling.Abstractions;

/// <summary>
/// Persists scheduler definitions, per-job status and execution history.
/// Implementations must degrade gracefully when the backing store is
/// missing or corrupted — see <see cref="JsonSchedulerStore"/>.
/// </summary>
public interface ISchedulerStore
{
    IReadOnlyList<ScheduledJobDefinition> LoadJobs();
    IReadOnlyList<ScheduledJobStatus> LoadStatus();
    IReadOnlyList<ScheduledJobExecution> LoadHistory();

    void SaveJobs(IReadOnlyList<ScheduledJobDefinition> jobs);
    void SaveStatus(IReadOnlyList<ScheduledJobStatus> statuses);
    void AppendHistory(ScheduledJobExecution execution);
}
