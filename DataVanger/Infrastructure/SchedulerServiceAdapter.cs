using System;
using DataVanger.Core;
using DataVanger.Core.Abstractions;

namespace DataVanger.Infrastructure;

/// <summary>
/// Adapter exposing <see cref="SchedulerHelper"/> as <see cref="ISchedulerService"/>.
/// </summary>
public sealed class SchedulerServiceAdapter : ISchedulerService
{
    public (bool ok, string msg) RegisterRecurring(
        string exePath,
        string friendlyName,
        string schedule,
        DateTime when,
        string dayOfWeek,
        ScanProfile profile)
        => SchedulerHelper.RegisterRecurring(exePath, friendlyName, schedule, when, dayOfWeek, profile);

    public (bool ok, string msg) Unregister(string taskName) => SchedulerHelper.Unregister(taskName);

    public bool Exists(string taskName) => SchedulerHelper.Exists();
}
