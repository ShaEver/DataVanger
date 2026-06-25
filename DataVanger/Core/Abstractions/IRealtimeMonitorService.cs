using System;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// Watches sensitive folders for new/renamed files and emits notifications
/// when a candidate looks worth scanning. Detection itself is delegated to
/// the engine via <see cref="SuspiciousFileCreated"/>.
/// </summary>
public interface IRealtimeMonitorService : IDisposable
{
    bool IsRunning { get; }

    /// <summary>Raised once per suspicious file with the absolute path.</summary>
    event Action<string>? SuspiciousFileCreated;

    void Start();
    void Stop();
}
