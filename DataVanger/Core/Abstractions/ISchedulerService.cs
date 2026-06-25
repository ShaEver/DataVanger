using System;
using DataVanger.Core;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// OS-scheduler integration. The current implementation talks to
/// <c>schtasks.exe</c> on Windows; the interface keeps the engine and UI
/// decoupled from that specific transport.
/// </summary>
public interface ISchedulerService
{
    (bool ok, string msg) RegisterRecurring(
        string exePath,
        string friendlyName,
        string schedule,
        DateTime when,
        string dayOfWeek,
        ScanProfile profile);

    (bool ok, string msg) Unregister(string taskName);

    bool Exists(string taskName);
}
