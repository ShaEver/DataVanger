using System;
using System.IO;
using DataVanger.Infrastructure.Runtime;
using DataVanger.Shared.Realtime;

namespace DataVanger.Infrastructure.FileSystem;

/// <summary>
/// Real user-mode adapter around <see cref="System.IO.FileSystemWatcher"/>.
///
/// Safety properties:
///   - Constructor never throws — if the watcher cannot be created, the
///     adapter starts in a degraded "not running" state and emits a
///     <see cref="RealtimeFileEventKind.WatcherError"/> on Start.
///   - The adapter NEVER locks any file. It only subscribes to event
///     notifications.
///   - Watcher buffer overflows / native errors degrade to a warning
///     event instead of crashing the host.
///   - Stop / Dispose are idempotent and short-circuit cleanly.
///   - No background threads are started by the adapter itself; the
///     underlying FileSystemWatcher uses the thread pool only when
///     <c>EnableRaisingEvents</c> is true.
/// </summary>
public sealed class FileSystemWatcherAdapter : IFileSystemWatcherAdapter
{
    private readonly object _gate = new();
    private readonly IRuntimeClock _clock;
    private FileSystemWatcher? _watcher;
    private bool _running;
    private bool _disposed;

    public string ProfileName { get; }
    public string Path { get; }
    public bool IsRunning
    {
        get { lock (_gate) return _running && !_disposed; }
    }

    public event Action<RealtimeFileEvent>? EventReceived;

    public FileSystemWatcherAdapter(RealtimeWatchProfile profile, IRuntimeClock? clock = null)
    {
        if (profile is null) throw new ArgumentNullException(nameof(profile));
        ProfileName = profile.Name ?? string.Empty;
        Path = profile.Path ?? string.Empty;
        _clock = clock ?? SystemRuntimeClock.Instance;

        try
        {
            // Construction is intentionally separated from Start so that
            // configuration validation failures show up as WatcherError
            // events rather than as exceptions from the orchestrator.
            _watcher = new FileSystemWatcher
            {
                Path = Path,
                IncludeSubdirectories = profile.IncludeSubdirectories,
                NotifyFilter = NotifyFilters.FileName
                             | NotifyFilters.LastWrite
                             | NotifyFilters.Size
                             | NotifyFilters.CreationTime,
                EnableRaisingEvents = false,
                InternalBufferSize = 32 * 1024,
            };
            _watcher.Created += OnCreated;
            _watcher.Changed += OnChanged;
            _watcher.Deleted += OnDeleted;
            _watcher.Renamed += OnRenamed;
            _watcher.Error   += OnError;
        }
        catch (Exception ex)
        {
            // Construction failure (missing directory, access denied,
            // invalid path, …) is non-fatal — the adapter stays in a
            // degraded state and will emit a WatcherError on Start.
            _watcher?.Dispose();
            _watcher = null;
            _constructorError = ex.Message;
        }
    }

    private readonly string? _constructorError;

    public bool Start()
    {
        lock (_gate)
        {
            if (_disposed) return false;
            if (_running) return true;

            if (_watcher is null)
            {
                Emit(new RealtimeFileEvent
                {
                    Kind = RealtimeFileEventKind.WatcherError,
                    Path = Path,
                    SourceProfile = ProfileName,
                    TimestampUtc = _clock.UtcNow,
                    Reason = _constructorError ?? "Watcher could not be created.",
                });
                return false;
            }

            try
            {
                _watcher.EnableRaisingEvents = true;
                _running = true;
                Emit(new RealtimeFileEvent
                {
                    Kind = RealtimeFileEventKind.WatcherStarted,
                    Path = Path,
                    SourceProfile = ProfileName,
                    TimestampUtc = _clock.UtcNow,
                });
                return true;
            }
            catch (Exception ex)
            {
                _running = false;
                Emit(new RealtimeFileEvent
                {
                    Kind = RealtimeFileEventKind.WatcherError,
                    Path = Path,
                    SourceProfile = ProfileName,
                    TimestampUtc = _clock.UtcNow,
                    Reason = ex.Message,
                });
                return false;
            }
        }
    }

    public void Stop()
    {
        lock (_gate)
        {
            if (_disposed || !_running) return;
            try
            {
                if (_watcher is not null) _watcher.EnableRaisingEvents = false;
            }
            catch
            {
                // Defensive: never propagate from Stop.
            }
            _running = false;
            Emit(new RealtimeFileEvent
            {
                Kind = RealtimeFileEventKind.WatcherStopped,
                Path = Path,
                SourceProfile = ProfileName,
                TimestampUtc = _clock.UtcNow,
            });
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            try
            {
                if (_watcher is not null)
                {
                    _watcher.EnableRaisingEvents = false;
                    _watcher.Created -= OnCreated;
                    _watcher.Changed -= OnChanged;
                    _watcher.Deleted -= OnDeleted;
                    _watcher.Renamed -= OnRenamed;
                    _watcher.Error   -= OnError;
                    _watcher.Dispose();
                    _watcher = null;
                }
            }
            catch
            {
                // Best-effort teardown only.
            }
            _running = false;
        }
    }

    private void OnCreated(object sender, FileSystemEventArgs e) =>
        Emit(new RealtimeFileEvent
        {
            Kind = RealtimeFileEventKind.Created,
            Path = e.FullPath,
            SourceProfile = ProfileName,
            TimestampUtc = _clock.UtcNow,
        });

    private void OnChanged(object sender, FileSystemEventArgs e) =>
        Emit(new RealtimeFileEvent
        {
            Kind = RealtimeFileEventKind.Changed,
            Path = e.FullPath,
            SourceProfile = ProfileName,
            TimestampUtc = _clock.UtcNow,
        });

    private void OnDeleted(object sender, FileSystemEventArgs e) =>
        Emit(new RealtimeFileEvent
        {
            Kind = RealtimeFileEventKind.Deleted,
            Path = e.FullPath,
            SourceProfile = ProfileName,
            TimestampUtc = _clock.UtcNow,
        });

    private void OnRenamed(object sender, RenamedEventArgs e) =>
        Emit(new RealtimeFileEvent
        {
            Kind = RealtimeFileEventKind.Renamed,
            Path = e.FullPath,
            OldPath = e.OldFullPath,
            SourceProfile = ProfileName,
            TimestampUtc = _clock.UtcNow,
        });

    private void OnError(object sender, ErrorEventArgs e)
    {
        Emit(new RealtimeFileEvent
        {
            Kind = RealtimeFileEventKind.WatcherError,
            Path = Path,
            SourceProfile = ProfileName,
            TimestampUtc = _clock.UtcNow,
            Reason = e.GetException()?.Message,
        });
    }

    private void Emit(RealtimeFileEvent ev)
    {
        try
        {
            EventReceived?.Invoke(ev);
        }
        catch
        {
            // The orchestrator is the single subscriber and must never
            // throw back into the watcher — but defend against a buggy
            // sink so the watcher process stays alive.
        }
    }
}
