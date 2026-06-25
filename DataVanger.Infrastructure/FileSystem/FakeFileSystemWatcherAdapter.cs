using System;
using DataVanger.Infrastructure.Runtime;
using DataVanger.Shared.Realtime;

namespace DataVanger.Infrastructure.FileSystem;

/// <summary>
/// Deterministic in-memory watcher used by tests. Has no real disk
/// dependency, no background threads, no admin requirement. Tests
/// drive it by calling <see cref="Raise"/> / <see cref="RaiseError"/>.
///
/// The fake intentionally exposes the same surface as the real adapter
/// (Start/Stop idempotent, EventReceived single channel, lifecycle
/// notifications) so the orchestrator cannot tell which one it owns.
/// </summary>
public sealed class FakeFileSystemWatcherAdapter : IFileSystemWatcherAdapter
{
    private readonly object _gate = new();
    private readonly IRuntimeClock _clock;
    private bool _running;
    private bool _disposed;

    public string ProfileName { get; }
    public string Path { get; }
    public bool IsRunning
    {
        get { lock (_gate) return _running && !_disposed; }
    }

    public bool FailOnStart { get; set; }
    public string? FailOnStartReason { get; set; }

    public event Action<RealtimeFileEvent>? EventReceived;

    public FakeFileSystemWatcherAdapter(RealtimeWatchProfile profile, IRuntimeClock? clock = null)
    {
        if (profile is null) throw new ArgumentNullException(nameof(profile));
        ProfileName = profile.Name ?? string.Empty;
        Path = profile.Path ?? string.Empty;
        _clock = clock ?? new FakeRuntimeClock();
    }

    public bool Start()
    {
        RealtimeFileEvent? toEmit;
        bool result;
        lock (_gate)
        {
            if (_disposed) return false;
            if (_running) return true;

            if (FailOnStart)
            {
                toEmit = new RealtimeFileEvent
                {
                    Kind = RealtimeFileEventKind.WatcherError,
                    Path = Path,
                    SourceProfile = ProfileName,
                    TimestampUtc = _clock.UtcNow,
                    Reason = FailOnStartReason ?? "Synthetic watcher start failure.",
                };
                result = false;
            }
            else
            {
                _running = true;
                toEmit = new RealtimeFileEvent
                {
                    Kind = RealtimeFileEventKind.WatcherStarted,
                    Path = Path,
                    SourceProfile = ProfileName,
                    TimestampUtc = _clock.UtcNow,
                };
                result = true;
            }
        }
        Emit(toEmit);
        return result;
    }

    public void Stop()
    {
        RealtimeFileEvent? toEmit = null;
        lock (_gate)
        {
            if (_disposed || !_running) return;
            _running = false;
            toEmit = new RealtimeFileEvent
            {
                Kind = RealtimeFileEventKind.WatcherStopped,
                Path = Path,
                SourceProfile = ProfileName,
                TimestampUtc = _clock.UtcNow,
            };
        }
        Emit(toEmit);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _running = false;
        }
    }

    /// <summary>
    /// Test-only helper: emit a normalized file event. The watcher
    /// only emits if it is currently running, so tests can verify
    /// Stop semantics.
    /// </summary>
    public void Raise(RealtimeFileEventKind kind, string path, string? oldPath = null, string? reason = null)
    {
        RealtimeFileEvent ev;
        lock (_gate)
        {
            if (_disposed || !_running) return;
            ev = new RealtimeFileEvent
            {
                Kind = kind,
                Path = path,
                OldPath = oldPath,
                SourceProfile = ProfileName,
                TimestampUtc = _clock.UtcNow,
                Reason = reason,
            };
        }
        Emit(ev);
    }

    /// <summary>
    /// Test-only helper to simulate an underlying watcher error.
    /// Errors are emitted even when the watcher is "running" because the
    /// real adapter forwards them through the same channel.
    /// </summary>
    public void RaiseError(string reason)
    {
        RealtimeFileEvent ev;
        lock (_gate)
        {
            if (_disposed) return;
            ev = new RealtimeFileEvent
            {
                Kind = RealtimeFileEventKind.WatcherError,
                Path = Path,
                SourceProfile = ProfileName,
                TimestampUtc = _clock.UtcNow,
                Reason = reason,
            };
        }
        Emit(ev);
    }

    private void Emit(RealtimeFileEvent? ev)
    {
        if (ev is null) return;
        try { EventReceived?.Invoke(ev); }
        catch { /* defensive: never let sinks crash the fake */ }
    }
}
