using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.ProtectedFiles;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Engine.ProtectedFiles;

/// <summary>
/// Default implementation of <see cref="IProtectedFilesActivityMonitor"/>
/// (Phase 2 / Step 07).
///
/// Pipeline:
///   RuntimeSecurityEvent (pipeline)
///   → ProtectedFilesActivityEventAdapter   (normalize/enrich)
///   → ActivityTracker / ProtectedFilesActivityState (bounded, TTL-cleaned)
///   → ActivityScoringPolicy                (conservative, explainable)
///   → ProtectedFilesEvidenceFactory        (evidence ONLY)
///   → SafeResponsePolicy (passive)         + optional sink/reporting
///
/// Development-mode / safety guarantees (mirroring the behavioral runtime
/// binding):
///   - No background threads, no timers, no loops. Events are processed
///     inline on the publishing thread; TTL cleanup is event-driven.
///     Tests are deterministic without sleeps.
///   - Disabled mode subscribes to nothing and emits no evidence.
///   - Every mode is passive: NEVER quarantines, kills, suspends, blocks
///     writes, injects, rolls back, or runs recovery/backup commands.
///   - All state is bounded (MaxTrackedProcesses / window caps) and
///     TTL-cleaned.
///   - Rate-limited (MaxEventsPerMinute) with overflow counted as drops.
///   - Development/build/excluded folders are NOT scored, so dotnet build,
///     test output and git operations never trip the monitor.
///   - StartAsync / StopAsync are idempotent and cancellation-aware.
///   - Fully disposable; StopAsync leaves no work behind.
///   - NEVER produces ConfirmedMalware (evidence is evidence only).
/// </summary>
public sealed class ProtectedFilesActivityMonitor
    : IProtectedFilesActivityMonitor, IRuntimeEventConsumer, IDisposable
{
    private readonly object _gate = new();
    private readonly ProtectedFilesActivityOptions _options;
    private readonly IRuntimeEventPipeline? _pipeline;
    private readonly IProtectedFilesActivityEvidenceSink? _evidenceSink;
    private readonly Func<DateTimeOffset> _now;

    private readonly ProtectedFilesActivityEventAdapter _adapter;
    private readonly ProtectedFolderPolicy _folderPolicy;
    private readonly ActivityScoringPolicy _scoring;
    private readonly SafeResponsePolicy _responsePolicy;
    private readonly ProtectedFilesEvidenceFactory _factory;
    private readonly ActivityTracker _tracker;

    private readonly LinkedList<ProtectedFilesActivityEvidence> _recentEvidence = new();
    private readonly LinkedList<string> _warnings = new();

    private long _eventsReceived;
    private long _observationsCreated;
    private long _evidenceGenerated;
    private long _eventsDropped;
    private long _recentAlertCount;

    // Fixed-window rate limiter (deterministic with an injected clock).
    private long _rateWindowMinute = long.MinValue;
    private int _rateWindowCount;

    private DateTimeOffset? _lastEventUtc;
    private bool _degraded;
    private string? _lastError;
    private ProtectedFilesActivityMonitorState _state = ProtectedFilesActivityMonitorState.Disabled;
    private bool _subscribed;
    private bool _disposed;

    public ProtectedFilesActivityMonitor(
        ProtectedFilesActivityOptions? options = null,
        IRuntimeEventPipeline? pipeline = null,
        IProtectedFilesActivityEvidenceSink? evidenceSink = null,
        Func<DateTimeOffset>? timeProvider = null)
    {
        _options = (options ?? ProtectedFilesActivityOptions.DevelopmentSafe()).WithSafeDefaults();
        _pipeline = pipeline;
        _evidenceSink = evidenceSink;
        _now = timeProvider ?? (() => DateTimeOffset.UtcNow);

        _adapter = new ProtectedFilesActivityEventAdapter(_options.EnableRecoveryIndicatorLabels);
        _folderPolicy = new ProtectedFolderPolicy(_options);
        _scoring = new ActivityScoringPolicy(_options);
        _responsePolicy = new SafeResponsePolicy(_options);
        _factory = new ProtectedFilesEvidenceFactory();
        _tracker = new ActivityTracker(_options);

        _state = _options.IsEnabled
            ? ProtectedFilesActivityMonitorState.Stopped
            : ProtectedFilesActivityMonitorState.Disabled;
    }

    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (_disposed) return Task.CompletedTask;

            if (!_options.IsEnabled)
            {
                _state = ProtectedFilesActivityMonitorState.Disabled;
                return Task.CompletedTask;
            }

            if (_state is ProtectedFilesActivityMonitorState.Running
                or ProtectedFilesActivityMonitorState.Passive
                or ProtectedFilesActivityMonitorState.DevelopmentSafe
                or ProtectedFilesActivityMonitorState.Degraded
                or ProtectedFilesActivityMonitorState.Starting)
            {
                return Task.CompletedTask; // idempotent
            }

            if (cancellationToken.IsCancellationRequested)
            {
                _state = ProtectedFilesActivityMonitorState.Stopped;
                return Task.FromCanceled(cancellationToken);
            }

            _state = ProtectedFilesActivityMonitorState.Starting;

            if (_pipeline is not null && !_subscribed)
            {
                _pipeline.Subscribe(this);
                _subscribed = true;
            }

            _state = ResolveRunningState();
            return Task.CompletedTask;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (_disposed) return Task.CompletedTask;

            if (_state == ProtectedFilesActivityMonitorState.Disabled && !_options.IsEnabled)
                return Task.CompletedTask;

            _state = ProtectedFilesActivityMonitorState.Stopping;

            if (_pipeline is not null && _subscribed)
            {
                _pipeline.Unsubscribe(this);
                _subscribed = false;
            }

            _tracker.Clear();
            _state = ProtectedFilesActivityMonitorState.Stopped;
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Runtime event consumer entry point. Inline, bounded, never throws,
    /// never acts. Honors cancellation cooperatively.
    /// </summary>
    public ValueTask HandleAsync(RuntimeSecurityEvent runtimeEvent, CancellationToken cancellationToken = default)
    {
        if (runtimeEvent is null) return ValueTask.CompletedTask;

        lock (_gate)
        {
            if (_disposed || !_options.IsEnabled) { _eventsDropped++; return ValueTask.CompletedTask; }
            if (_state is not (ProtectedFilesActivityMonitorState.Running
                or ProtectedFilesActivityMonitorState.Passive
                or ProtectedFilesActivityMonitorState.DevelopmentSafe
                or ProtectedFilesActivityMonitorState.Degraded))
            {
                _eventsDropped++;
                return ValueTask.CompletedTask;
            }
            if (cancellationToken.IsCancellationRequested) { _eventsDropped++; return ValueTask.CompletedTask; }

            var now = _now();
            _eventsReceived++;
            _lastEventUtc = runtimeEvent.TimestampUtc == default ? now : runtimeEvent.TimestampUtc;

            if (!AllowByRateLimit(now))
            {
                _eventsDropped++;
                MarkDegraded("Protected-files monitor rate limit reached; some events were dropped.");
                return ValueTask.CompletedTask;
            }

            try
            {
                ProcessEvent(runtimeEvent, now);
            }
            catch (Exception ex)
            {
                _lastError = $"{ex.GetType().Name}: {Trim(ex.Message)}";
                AddWarning($"Event handling failed: {_lastError}");
            }
        }

        return ValueTask.CompletedTask;
    }

    public ProtectedFilesActivityHealthSnapshot GetHealthSnapshot()
    {
        lock (_gate)
        {
            return new ProtectedFilesActivityHealthSnapshot
            {
                Mode = _options.Mode,
                State = _state,
                IsEnabled = _options.IsEnabled,
                IsPassive = _state is ProtectedFilesActivityMonitorState.Passive
                    or ProtectedFilesActivityMonitorState.DevelopmentSafe,
                IsDegraded = _degraded,
                ProtectedFolderMonitoringEnabled = _options.EnableProtectedFolderMonitoring,
                EntropySamplingEnabled = _options.EnableEntropySampling,
                RecoveryIndicatorLabelsEnabled = _options.EnableRecoveryIndicatorLabels,
                ActiveResponseEnabled = _options.EnableActiveResponseHooks,
                EventsReceived = _eventsReceived,
                ObservationsCreated = _observationsCreated,
                EvidenceGenerated = _evidenceGenerated,
                EventsDropped = _eventsDropped,
                RecentAlertCount = _recentAlertCount,
                TrackedProcessCount = _tracker.Count,
                TrackedDirectoryCount = _tracker.TotalTrackedDirectories,
                LastWarning = _warnings.Count == 0 ? null : _warnings.Last!.Value,
                LastError = _lastError,
                LastEventUtc = _lastEventUtc,
            };
        }
    }

    /// <summary>Bounded snapshot of the most recent activity evidence (for tests/reporting).</summary>
    public IReadOnlyList<ProtectedFilesActivityEvidence> GetRecentEvidence()
    {
        lock (_gate)
        {
            return _recentEvidence.Count == 0
                ? Array.Empty<ProtectedFilesActivityEvidence>()
                : new List<ProtectedFilesActivityEvidence>(_recentEvidence);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            if (_pipeline is not null && _subscribed)
            {
                _pipeline.Unsubscribe(this);
                _subscribed = false;
            }
            _tracker.Clear();
            _recentEvidence.Clear();
            _disposed = true;
            _state = ProtectedFilesActivityMonitorState.Stopped;
        }
    }

    // ----- internals (all called under _gate) -------------------------------

    private void ProcessEvent(RuntimeSecurityEvent runtimeEvent, DateTimeOffset now)
    {
        var observation = _adapter.Map(runtimeEvent);
        if (observation is null) return;
        _observationsCreated++;

        // Excluded paths are ignored entirely for scoring (recovery labels
        // are still honored below since they ride on non-file events).
        var pathClass = PathClass.Other;
        if (observation.Kind is not ProtectedFileObservationKind.RecoveryIndicator)
        {
            pathClass = _folderPolicy.Classify(observation.SubjectPath);

            // Development-safe and excluded folders never contribute to
            // scoring. This is what keeps dotnet build / test output / git
            // operations from ever tripping the monitor.
            if (pathClass is PathClass.Excluded or PathClass.DevelopmentSafe)
            {
                // Keep TTL cleanup moving even on ignored events.
                _tracker.Prune(now);
                return;
            }
        }

        var key = ResolveCorrelationKey(observation);
        var state = _tracker.GetOrCreate(key, now, out var evicted);
        if (evicted)
        {
            _eventsDropped++;
            MarkDegraded("Protected-files monitor state limit reached; some events were dropped.");
        }

        // Enrich tracked state with process identity.
        if (observation.ProcessId is int pid && pid > 0) state.ProcessId = pid;
        if (!string.IsNullOrEmpty(observation.ProcessName)) state.ProcessName = observation.ProcessName;
        if (!string.IsNullOrEmpty(observation.ProcessImagePath)) state.ProcessImagePath = observation.ProcessImagePath;

        RecordObservation(state, observation, pathClass, now);

        // Score and (conservatively, escalation-only) emit evidence.
        var score = _scoring.Score(state, now);
        MaybeEmitEvidence(state, score, now);
    }

    private void RecordObservation(
        ProtectedFilesActivityState state,
        ProtectedFileObservation o,
        PathClass pathClass,
        DateTimeOffset now)
    {
        switch (o.Kind)
        {
            case ProtectedFileObservationKind.FileCreated:
                state.MutationProfile.RecordCreated();
                state.ModificationWindow.Record(now);
                break;
            case ProtectedFileObservationKind.FileModified:
                state.MutationProfile.RecordModified();
                state.ModificationWindow.Record(now);
                break;
            case ProtectedFileObservationKind.FileDeleted:
                state.MutationProfile.RecordDeleted();
                state.DeleteWindow.Record(now);
                break;
            case ProtectedFileObservationKind.FileRenamed:
                state.MutationProfile.RecordRenamed();
                state.RenameWindow.Record(now);
                if (_options.EnableExtensionTransitionAnalysis)
                {
                    var transition = ExtensionTransitionAnalyzer.GetTransition(o.PreviousPath, o.SubjectPath);
                    if (transition.HasChange)
                    {
                        var suspicious = ExtensionTransitionAnalyzer.IsSuspiciousTransition(transition);
                        state.MutationProfile.RecordTransition(transition.Key, suspicious);
                    }
                }
                break;
            case ProtectedFileObservationKind.RecoveryIndicator:
                if (_options.EnableRecoveryIndicatorLabels && o.RecoveryIndicators.Count > 0)
                {
                    state.AddRecoveryIndicators(o.RecoveryIndicators);
                }
                return; // no file path bookkeeping for indicator-only events
        }

        // Common file-event bookkeeping.
        state.MutationProfile.RecordBytes(o.ByteCount);
        state.MutationProfile.RecordDirectory(ProtectedFolderPolicy.GetDirectory(o.SubjectPath));

        if (pathClass == PathClass.Protected)
        {
            state.TouchProtectedFolder(ProtectedFolderPolicy.GetDirectory(o.SubjectPath) ?? o.SubjectPath);
        }

        if (_options.EnableEntropySampling && (o.EntropyAfter is not null || o.EntropyBefore is not null))
        {
            var high = o.EntropyAfter is double ea && EntropyDeltaAnalyzer.IsHighEntropy(ea);
            var increase = EntropyDeltaAnalyzer.IsSuspiciousIncrease(o.EntropyBefore, o.EntropyAfter);
            state.MutationProfile.RecordEntropy(high, increase);
        }

        // Recovery labels can also ride along a file event's metadata.
        if (_options.EnableRecoveryIndicatorLabels && o.RecoveryIndicators.Count > 0)
        {
            state.AddRecoveryIndicators(o.RecoveryIndicators);
        }
    }

    private void MaybeEmitEvidence(ProtectedFilesActivityState state, ActivityScore score, DateTimeOffset now)
    {
        // Emit only at Suspicious or higher, and only on escalation beyond
        // the highest level already emitted for this key. This is the core
        // anti-amplification / anti-spam guard.
        if (score.Level < ProtectedFilesActivitySeverity.Suspicious) return;
        if (score.Level <= state.HighestEmittedSeverity) return;

        state.HighestEmittedSeverity = score.Level;

        var response = _responsePolicy.Decide(score.Level);
        if (!response.EmitEvidence) return;

        var evidence = _factory.Create(state, score, response, now);
        _evidenceGenerated++;
        _recentAlertCount++;
        RetainEvidence(evidence);
        DispatchEvidence(evidence, response);
    }

    private void DispatchEvidence(ProtectedFilesActivityEvidence evidence, SafeResponse response)
    {
        // Passive observer notification only — never an action.
        if (_evidenceSink is not null)
        {
            try { _evidenceSink.OnEvidence(evidence); }
            catch (Exception ex) { AddWarning($"Evidence sink threw {ex.GetType().Name}: {Trim(ex.Message)}"); }
        }

        // Optional reporting telemetry. Off by default and guarded against
        // feedback loops: it is published as a RansomwareSuspicion event
        // sourced AntiRansomware, and HandleAsync only consumes file
        // categories, so it ignores this event.
        if (response.EmitReportTelemetry && _pipeline is not null)
        {
            try
            {
                var ev = _factory.ToRuntimeEvent(evidence);
                _ = _pipeline.PublishAsync(ev);
            }
            catch (Exception ex)
            {
                AddWarning($"Evidence republish failed: {ex.GetType().Name}: {Trim(ex.Message)}");
            }
        }
    }

    private void RetainEvidence(ProtectedFilesActivityEvidence evidence)
    {
        _recentEvidence.AddLast(evidence);
        while (_recentEvidence.Count > _options.MaxRetainedEvidence)
        {
            _recentEvidence.RemoveFirst();
        }
    }

    private string ResolveCorrelationKey(ProtectedFileObservation o)
    {
        if (_options.EnableProcessContextCorrelation)
        {
            if (o.ProcessId is int pid && pid > 0) return $"pid:{pid}";
            if (!string.IsNullOrWhiteSpace(o.ProcessName)) return $"name:{o.ProcessName!.ToLowerInvariant()}";
        }
        return "unknown";
    }

    private bool AllowByRateLimit(DateTimeOffset now)
    {
        var minute = now.ToUnixTimeSeconds() / 60;
        if (minute != _rateWindowMinute)
        {
            _rateWindowMinute = minute;
            _rateWindowCount = 0;
        }
        if (_rateWindowCount >= _options.MaxEventsPerMinute) return false;
        _rateWindowCount++;
        return true;
    }

    private ProtectedFilesActivityMonitorState ResolveRunningState()
    {
        if (_degraded) return ProtectedFilesActivityMonitorState.Degraded;
        return _options.Mode switch
        {
            ProtectedFilesActivityMode.Development or ProtectedFilesActivityMode.Test
                => ProtectedFilesActivityMonitorState.DevelopmentSafe,
            ProtectedFilesActivityMode.Passive or ProtectedFilesActivityMode.AlertOnly
                => ProtectedFilesActivityMonitorState.Passive,
            _ => ProtectedFilesActivityMonitorState.Running,
        };
    }

    private void MarkDegraded(string warning)
    {
        _degraded = true;
        if (_state is ProtectedFilesActivityMonitorState.Running
            or ProtectedFilesActivityMonitorState.Passive
            or ProtectedFilesActivityMonitorState.DevelopmentSafe)
        {
            _state = ProtectedFilesActivityMonitorState.Degraded;
        }
        AddWarning(warning);
    }

    private void AddWarning(string warning)
    {
        if (string.IsNullOrWhiteSpace(warning)) return;
        _warnings.AddLast(warning);
        while (_warnings.Count > _options.MaxRetainedWarnings)
        {
            _warnings.RemoveFirst();
        }
    }

    private static string Trim(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        const int max = 240;
        return value!.Length <= max ? value : value.Substring(0, max) + "...";
    }
}
