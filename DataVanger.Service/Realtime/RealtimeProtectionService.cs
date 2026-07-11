using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Realtime;
using DataVanger.Infrastructure.FileSystem;
using DataVanger.Infrastructure.Runtime;
using DataVanger.Service.Protection;
using DataVanger.Shared.Realtime;

namespace DataVanger.Service.Realtime;

/// <summary>
/// User-mode real-time file protection orchestrator.
///
/// Owns:
///   - Watcher lifecycle (start/stop/dispose, graceful degradation per
///     profile).
///   - Event normalization through the eligibility filter.
///   - Debounce/coalescing window.
///   - Bounded scan queue + path-level coalescing.
///   - Tick-driven worker loop (manual or auto) — never spins up
///     fire-and-forget background loops; AutoRun mode owns a single
///     cooperative task that exits when StopAsync / Dispose is called.
///   - Conservative response policy through the decision engine.
///   - Structured event publication for logs/status/reporting.
///
/// Anti-FP guarantees enforced by this class:
///   - Real-time telemetry NEVER becomes a malware verdict by itself —
///     all verdicts originate from the dispatcher (engine + classifier).
///   - Quarantine is only "authorized" when the decision engine says so
///     AND the orchestrator is NOT in PassiveMode.
///   - Watcher errors, queue overflow, locked files, missing paths,
///     and engine failures degrade gracefully to warnings.
///   - PassiveMode and Enabled=false short-circuit any destructive
///     branch.
///
/// Development-safety:
///   - DevelopmentMode (or per-profile DevelopmentSafe) inserts the
///     bin/obj/.git/.vs/TestResults/coverage exclusion list before any
///     event reaches the scan queue.
///   - Tests should construct with a <see cref="FakeFileSystemWatcherFactory"/>
///     and a <see cref="FakeRuntimeClock"/>, then drive the pipeline
///     via <see cref="ProcessOnceAsync"/>. AutoRun is OPT-IN.
/// </summary>
public sealed class RealtimeProtectionService : IRealtimeProtectionService
{
    private readonly object _gate = new();
    private readonly RealtimeProtectionOptions _options;
    private readonly IFileSystemWatcherFactory _watcherFactory;
    private readonly IFileStabilityProbe _stabilityProbe;
    private readonly IRealtimeScanDispatcher _dispatcher;
    private readonly IRealtimeScanCache _cache;
    private readonly IRealtimeProtectionDecisionEngine _decisionEngine;
    private readonly IRealtimeProtectionEventSink _sink;
    private readonly IRuntimeClock _clock;
    private readonly RealtimeEligibilityFilter _eligibility;
    private readonly RealtimeEventDebouncer _debouncer;
    private readonly RealtimeScanQueue _queue;
    private readonly List<IFileSystemWatcherAdapter> _watchers = new();
    private readonly HashSet<string> _degradedProfiles = new(StringComparer.OrdinalIgnoreCase);

    private long _eventsObserved;
    private long _filesScanned;
    private long _duplicatesSuppressed;
    private long _filesSkipped;
    private long _warnings;
    private DateTimeOffset? _lastEventUtc;
    private DateTimeOffset? _lastScanUtc;

    private string _state = "NotStarted";
    private bool _disposed;

    public RealtimeProtectionService(
        RealtimeProtectionOptions options,
        IFileSystemWatcherFactory watcherFactory,
        IFileStabilityProbe stabilityProbe,
        IRealtimeScanDispatcher dispatcher,
        IRealtimeScanCache cache,
        IRealtimeProtectionDecisionEngine decisionEngine,
        IRealtimeProtectionEventSink sink,
        IRuntimeClock? clock = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _watcherFactory = watcherFactory ?? throw new ArgumentNullException(nameof(watcherFactory));
        _stabilityProbe = stabilityProbe ?? throw new ArgumentNullException(nameof(stabilityProbe));
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _decisionEngine = decisionEngine ?? throw new ArgumentNullException(nameof(decisionEngine));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _clock = clock ?? SystemRuntimeClock.Instance;
        _eligibility = new RealtimeEligibilityFilter(_options);
        _debouncer = new RealtimeEventDebouncer(_options.DebounceWindow, () => _clock.UtcNow);
        _queue = new RealtimeScanQueue(_options.MaxQueueLength);
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                _state = "Stopped";
                return Task.CompletedTask;
            }

            if (_state == "Running" || _state == "Degraded" || _state == "Starting") return Task.CompletedTask;

            if (cancellationToken.IsCancellationRequested)
            {
                _state = "Stopped";
                return Task.FromCanceled(cancellationToken);
            }

            _state = "Starting";

            if (!_options.Enabled)
            {
                _state = "Disabled";
                Publish(new RealtimeProtectionEvent
                {
                    Kind = RealtimeProtectionEventKind.Stopped,
                    TimestampUtc = _clock.UtcNow,
                    Message = "Realtime protection disabled by configuration; no watchers started.",
                });
                return Task.CompletedTask;
            }

            Publish(new RealtimeProtectionEvent
            {
                Kind = RealtimeProtectionEventKind.Started,
                TimestampUtc = _clock.UtcNow,
                Message = _options.PassiveMode
                    ? "Realtime protection started in passive mode."
                    : "Realtime protection started.",
            });

            int active = 0;
            foreach (var profile in _options.WatchProfiles)
            {
                if (!profile.Enabled)
                {
                    _degradedProfiles.Add(profile.Name);
                    Publish(new RealtimeProtectionEvent
                    {
                        Kind = RealtimeProtectionEventKind.WatchProfileDegraded,
                        Profile = profile.Name,
                        TimestampUtc = _clock.UtcNow,
                        Message = "Profile disabled by configuration.",
                    });
                    continue;
                }

                if (string.IsNullOrWhiteSpace(profile.Path) || !Directory.Exists(profile.Path))
                {
                    _degradedProfiles.Add(profile.Name);
                    Interlocked.Increment(ref _warnings);
                    Publish(new RealtimeProtectionEvent
                    {
                        Kind = RealtimeProtectionEventKind.WatchProfileDegraded,
                        Profile = profile.Name,
                        Path = profile.Path,
                        TimestampUtc = _clock.UtcNow,
                        Message = "Profile path is missing or unavailable; degraded.",
                    });
                    continue;
                }

                IFileSystemWatcherAdapter watcher;
                try { watcher = _watcherFactory.Create(profile); }
                catch (Exception ex)
                {
                    _degradedProfiles.Add(profile.Name);
                    Interlocked.Increment(ref _warnings);
                    Publish(new RealtimeProtectionEvent
                    {
                        Kind = RealtimeProtectionEventKind.WatchProfileDegraded,
                        Profile = profile.Name,
                        Path = profile.Path,
                        TimestampUtc = _clock.UtcNow,
                        Message = $"Watcher factory failed: {ex.Message}",
                    });
                    continue;
                }

                watcher.EventReceived += ev => OnWatcherEvent(profile, ev);
                _watchers.Add(watcher);

                if (watcher.Start())
                {
                    active++;
                    Publish(new RealtimeProtectionEvent
                    {
                        Kind = RealtimeProtectionEventKind.WatchProfileStarted,
                        Profile = profile.Name,
                        Path = profile.Path,
                        TimestampUtc = _clock.UtcNow,
                    });
                }
                else
                {
                    _degradedProfiles.Add(profile.Name);
                    Interlocked.Increment(ref _warnings);
                    Publish(new RealtimeProtectionEvent
                    {
                        Kind = RealtimeProtectionEventKind.WatchProfileDegraded,
                        Profile = profile.Name,
                        Path = profile.Path,
                        TimestampUtc = _clock.UtcNow,
                        Message = "Watcher could not start; profile is degraded.",
                    });
                }
            }

            _state = active > 0
                ? (_degradedProfiles.Count > 0 ? "Degraded" : "Running")
                : "Degraded";

            return Task.CompletedTask;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        List<IFileSystemWatcherAdapter> snapshot;
        lock (_gate)
        {
            if (_disposed) { _state = "Stopped"; return Task.CompletedTask; }
            if (_state == "Stopped" || _state == "NotStarted" || _state == "Disabled")
            {
                _state = _state == "Disabled" ? "Disabled" : "Stopped";
                return Task.CompletedTask;
            }
            _state = "Stopping";
            snapshot = new List<IFileSystemWatcherAdapter>(_watchers);
        }

        foreach (var w in snapshot)
        {
            try { w.Stop(); } catch (System.Exception) { Interlocked.Increment(ref _warnings); }
        }

        lock (_gate)
        {
            _debouncer.Clear();
            _queue.Clear();
            _state = "Stopped";
            Publish(new RealtimeProtectionEvent
            {
                Kind = RealtimeProtectionEventKind.Stopped,
                TimestampUtc = _clock.UtcNow,
                Message = "Realtime protection stopped.",
            });
        }
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        List<IFileSystemWatcherAdapter> snapshot;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            snapshot = new List<IFileSystemWatcherAdapter>(_watchers);
            _watchers.Clear();
        }
        foreach (var w in snapshot)
        {
            try { w.Dispose(); } catch (System.Exception) { /* best-effort */ }
        }
        lock (_gate)
        {
            _debouncer.Clear();
            _queue.Clear();
            _state = "Stopped";
        }
    }

    public RealtimeProtectionStatus GetStatusSnapshot()
    {
        lock (_gate)
        {
            int active = 0;
            foreach (var w in _watchers) if (w.IsRunning) active++;
            return new RealtimeProtectionStatus
            {
                Enabled = _options.Enabled,
                PassiveMode = _options.PassiveMode,
                DevelopmentMode = _options.DevelopmentMode,
                State = _state,
                ActiveWatchers = active,
                DegradedWatchers = _degradedProfiles.Count,
                PendingQueueCount = _queue.Count + _debouncer.PendingCount,
                EventsObserved = Interlocked.Read(ref _eventsObserved),
                FilesScanned = Interlocked.Read(ref _filesScanned),
                DuplicatesSuppressed = Interlocked.Read(ref _duplicatesSuppressed),
                FilesSkipped = Interlocked.Read(ref _filesSkipped),
                Warnings = Interlocked.Read(ref _warnings),
                LastEventUtc = _lastEventUtc,
                LastScanUtc = _lastScanUtc,
            };
        }
    }

    /// <summary>
    /// Drives a single pipeline pass: drain the debouncer, enqueue eligible
    /// requests, then drain up to <see cref="RealtimeProtectionOptions.MaxConcurrentScans"/>
    /// scan requests through the dispatcher.
    ///
    /// Tests call this directly so the orchestrator can be stepped
    /// deterministically without timers or sleeps. Production wires
    /// this into a cooperative loop (or an external scheduler).
    /// </summary>
    public async Task ProcessOnceAsync(CancellationToken cancellationToken)
    {
        if (_disposed) return;
        if (!_options.Enabled) return;

        cancellationToken.ThrowIfCancellationRequested();

        // 1. Move ready debounced events into the queue.
        var ready = _debouncer.Drain();
        foreach (var ev in ready)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await TryEnqueueScanAsync(ev, cancellationToken).ConfigureAwait(false);
        }

        // 2. Drain up to MaxConcurrentScans requests sequentially.
        // Sequential processing keeps the dispatcher predictable in
        // tests; MaxConcurrentScans=1 by default keeps engine pressure
        // low and avoids the need for SemaphoreSlim plumbing.
        int budget = Math.Max(1, _options.MaxConcurrentScans);
        for (int i = 0; i < budget; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_queue.TryDequeue(out var request) || request is null) break;
            await ExecuteScanAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }

    private void OnWatcherEvent(RealtimeWatchProfile profile, RealtimeFileEvent ev)
    {
        if (ev is null) return;
        Interlocked.Increment(ref _eventsObserved);
        _lastEventUtc = ev.TimestampUtc;

        switch (ev.Kind)
        {
            case RealtimeFileEventKind.WatcherStarted:
            case RealtimeFileEventKind.WatcherStopped:
                return; // lifecycle only

            case RealtimeFileEventKind.WatcherError:
                Interlocked.Increment(ref _warnings);
                lock (_gate) _degradedProfiles.Add(profile.Name);
                Publish(new RealtimeProtectionEvent
                {
                    Kind = RealtimeProtectionEventKind.WatcherError,
                    Profile = profile.Name,
                    Path = ev.Path,
                    Message = ev.Reason,
                    TimestampUtc = ev.TimestampUtc,
                });
                return;
        }

        if (!_eligibility.TryAccept(ev, profile, out var skipReason))
        {
            Interlocked.Increment(ref _filesSkipped);
            Publish(new RealtimeProtectionEvent
            {
                Kind = RealtimeProtectionEventKind.FileSkipped,
                Profile = profile.Name,
                Path = ev.Path,
                Message = skipReason,
                TimestampUtc = ev.TimestampUtc,
            });
            return;
        }

        _debouncer.Submit(ev);
    }

    private async Task TryEnqueueScanAsync(RealtimeFileEvent ev, CancellationToken cancellationToken)
    {
        // Stability probe gates the scan submission.
        FileStabilityResult stability;
        try
        {
            stability = await _stabilityProbe
                .ProbeAsync(ev.Path, _options.MaxRealtimeScanFileSizeBytes, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _warnings);
            Publish(new RealtimeProtectionEvent
            {
                Kind = RealtimeProtectionEventKind.Warning,
                Path = ev.Path,
                Message = $"Stability probe failed: {ex.Message}",
                TimestampUtc = _clock.UtcNow,
            });
            return;
        }

        if (!stability.IsStable)
        {
            Interlocked.Increment(ref _filesSkipped);
            Publish(new RealtimeProtectionEvent
            {
                Kind = RealtimeProtectionEventKind.FileSkipped,
                Path = ev.Path,
                Message = $"Not stable: {stability.Outcome} {stability.Reason}".Trim(),
                TimestampUtc = _clock.UtcNow,
            });
            return;
        }

        var request = new RealtimeScanRequest
        {
            Path = ev.Path,
            TriggerKind = ev.Kind,
            SourceProfile = ev.SourceProfile,
            EnqueuedAtUtc = _clock.UtcNow,
            FileLength = stability.Length,
            LastWriteUtc = stability.LastWriteUtc,
        };

        if (!_queue.TryEnqueue(request))
        {
            Interlocked.Increment(ref _warnings);
            Publish(new RealtimeProtectionEvent
            {
                Kind = RealtimeProtectionEventKind.QueueOverflow,
                Path = ev.Path,
                Message = $"Scan queue full (capacity {_queue.Capacity}); request dropped.",
                TimestampUtc = _clock.UtcNow,
            });
            return;
        }

        Publish(new RealtimeProtectionEvent
        {
            Kind = RealtimeProtectionEventKind.ScanRequested,
            Path = ev.Path,
            Profile = ev.SourceProfile,
            TimestampUtc = _clock.UtcNow,
        });
    }

    private async Task ExecuteScanAsync(RealtimeScanRequest request, CancellationToken cancellationToken)
    {
        if (_cache.TryGet(request, out var cached) && cached is not null)
        {
            Interlocked.Increment(ref _duplicatesSuppressed);
            _lastScanUtc = _clock.UtcNow;
            Publish(new RealtimeProtectionEvent
            {
                Kind = RealtimeProtectionEventKind.DuplicateSuppressed,
                Path = request.Path,
                Verdict = cached.Verdict,
                TimestampUtc = _clock.UtcNow,
                Message = "Result served from realtime scan cache.",
            });
            ApplyDecision(cached);
            return;
        }

        RealtimeScanResult result;
        try
        {
            result = await _dispatcher.DispatchAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _warnings);
            Publish(new RealtimeProtectionEvent
            {
                Kind = RealtimeProtectionEventKind.ScanFailed,
                Path = request.Path,
                TimestampUtc = _clock.UtcNow,
                Message = ex.Message,
            });
            return;
        }

        Interlocked.Increment(ref _filesScanned);
        _lastScanUtc = _clock.UtcNow;

        if (result.Failed)
        {
            Interlocked.Increment(ref _warnings);
            Publish(new RealtimeProtectionEvent
            {
                Kind = RealtimeProtectionEventKind.ScanFailed,
                Path = request.Path,
                Verdict = result.Verdict,
                TimestampUtc = result.CompletedAtUtc,
                Message = result.FailureReason,
            });
        }
        else
        {
            _cache.Store(request, result);
            Publish(new RealtimeProtectionEvent
            {
                Kind = RealtimeProtectionEventKind.ScanCompleted,
                Path = request.Path,
                Verdict = result.Verdict,
                TimestampUtc = result.CompletedAtUtc,
                Message = result.Message,
            });
        }

        ApplyDecision(result);
    }

    private void ApplyDecision(RealtimeScanResult result)
    {
        RealtimeProtectionDecision decision;
        try { decision = _decisionEngine.Decide(result, _options); }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _warnings);
            Publish(new RealtimeProtectionEvent
            {
                Kind = RealtimeProtectionEventKind.Warning,
                Path = result.Path,
                TimestampUtc = _clock.UtcNow,
                Message = $"Decision engine failed: {ex.Message}",
            });
            return;
        }

        Publish(new RealtimeProtectionEvent
        {
            Kind = RealtimeProtectionEventKind.DecisionMade,
            Path = decision.Path,
            Verdict = decision.Verdict,
            Action = decision.RecommendedAction,
            ActionAuthorized = decision.ActionAuthorized,
            Message = decision.Reason,
            TimestampUtc = decision.DecidedAtUtc,
        });

        // This phase intentionally does NOT execute the destructive
        // branch even when authorized — quarantine v2 / response
        // enforcement is owned by later phases. The decision is
        // reported so existing reporting/forensics can act on it.
    }

    private void Publish(RealtimeProtectionEvent ev)
    {
        try { _sink.Publish(ev); }
        catch (System.Exception)
        {
            Interlocked.Increment(ref _warnings);
        }
    }
}
