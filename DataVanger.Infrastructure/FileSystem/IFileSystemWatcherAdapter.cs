using System;
using DataVanger.Shared.Realtime;

namespace DataVanger.Infrastructure.FileSystem;

/// <summary>
/// User-mode file system watcher abstraction. The orchestrator
/// subscribes to <see cref="EventReceived"/> and treats every emission
/// as conservative telemetry — never as confirmation of malice.
///
/// Implementations:
///   - <c>FileSystemWatcherAdapter</c> wraps System.IO.FileSystemWatcher.
///   - <c>FakeFileSystemWatcherAdapter</c> is deterministic and used by
///     tests; no real disk I/O, no admin, no background threads.
/// </summary>
public interface IFileSystemWatcherAdapter : IDisposable
{
    string ProfileName { get; }
    string Path { get; }
    bool IsRunning { get; }

    event Action<RealtimeFileEvent>? EventReceived;

    /// <summary>
    /// Start observing. Implementations must never throw — failures
    /// must be surfaced as a WatcherError <see cref="RealtimeFileEvent"/>
    /// instead. Returns true if the watcher reached a running state.
    /// </summary>
    bool Start();

    void Stop();
}
