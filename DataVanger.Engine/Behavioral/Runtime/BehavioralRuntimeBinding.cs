using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Behavioral.Runtime;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Engine.Behavioral.Runtime;

/// <summary>
/// Default implementation of <see cref="IBehavioralRuntimeBinding"/>
/// (Phase 2 / Step 06).
///
/// Pipeline:
///   RuntimeSecurityEvent (pipeline)
///   → BehavioralRuntimeEventAdapter   (normalize/enrich)
///   → BehavioralCorrelationState      (bounded, TTL-cleaned lineage)
///   → BehavioralRuntimeRuleEvaluator  (conservative runtime rules)
///   → BehavioralRuntimeEvidence       (evidence ONLY)
///   → optional evidence sink + optional reporting telemetry
///
/// Development-mode / safety guarantees:
///   - No background threads, no timers, no loops. Events are processed
///     inline on the publishing thread; TTL cleanup is event-driven.
///     Tests are deterministic without sleeps.
///   - Disabled mode subscribes to nothing and emits no evidence.
///   - Passive / development modes generate evidence but NEVER act.
///   - All state is bounded (MaxTrackedProcesses) and TTL-cleaned.
///   - Rate-limited (MaxEventsPerMinute) with overflow counted as drops.
///   - StartAsync / StopAsync are idempotent and cancellation-aware.
///   - Fully disposable; StopAsync leaves no work behind.
///   - NEVER quarantines, kills, suspends, blocks, or injects.
///   - NEVER produces ConfirmedMalware (evidence is evidence only).
/// </summary>
public sealed class BehavioralRuntimeBinding : IBehavioralRuntimeBinding, IRuntimeEventConsumer, IDisposable
{
    private readonly object _gate = new();
    private readonly BehavioralRuntimeBindingOptions _options;
    private readonly IRuntimeEventPipeline? _pipeline;
    private readonly IBehavioralRuntimeEvidenceSink? _evidenceSink;
    private readonly Func<DateTimeOffset> _now;

    private readonly BehavioralRuntimeEventAdapter _adapter;
    private readonly BehavioralRuntimeRuleEvaluator _evaluator;
    private readonly BehavioralRuntimeEvidenceFactory _factory;
    private readonly BehavioralCorrelationState _correlation;

    private readonly LinkedList<BehavioralRuntimeEvidence> _recentEvidence = new();
    private readonly LinkedList<string> _warnings = new();

    private long _eventsReceived;
    private long _observationsCreated;
    private long _evidenceGenerated;
    private long _eventsDropped;

    // Fixed-window rate limiter (deterministic with an injected clock).
    private long _rateWindowMinute = long.MinValue;
    private int _rateWindowCount;

    private DateTimeOffset? _lastEventUtc;
    private bool _degraded;
    private BehavioralRuntimeBindingState _state = BehavioralRuntimeBindingState.Disabled;
    private bool _subscribed;
    private bool _disposed;

    public BehavioralRuntimeBinding(
        BehavioralRuntimeBindingOptions? options = null,
        IRuntimeEventPipeline? pipeline = null,
        IBehavioralRuntimeEvidenceSink? evidenceSink = null,
        Func<DateTimeOffset>? timeProvider = null)
    {
        _options = (options ?? BehavioralRuntimeBindingOptions.DevelopmentSafe()).WithSafeDefaults();
        _pipeline = pipeline;
        _evidenceSink = evidenceSink;
        _now = timeProvider ?? (() => DateTimeOffset.UtcNow);

        _factory = new BehavioralRuntimeEvidenceFactory();
        _adapter = new BehavioralRuntimeEventAdapter(_options.EnablePowerShellIndicators);
        _evaluator = new BehavioralRuntimeRuleEvaluator(_options, _factory);
        _correlation = new BehavioralCorrelationState(_options.MaxTrackedProcesses, _options.ProcessStateTtl);

        _state = _options.Enabled ? BehavioralRuntimeBindingState.Stopped : BehavioralRuntimeBindingState.Disabled;
    }

    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (_disposed) return Task.CompletedTask;

            if (!_options.Enabled)
            {
                _state = BehavioralRuntimeBindingState.Disabled;
                return Task.CompletedTask;
            }

            if (_state is BehavioralRuntimeBindingState.Running
                or BehavioralRuntimeBindingState.Passive
                or BehavioralRuntimeBindingState.DevelopmentSafe
                or BehavioralRuntimeBindingState.Degraded
                or BehavioralRuntimeBindingState.Starting)
            {
                // Idempotent — already running.
                return Task.CompletedTask;
            }

            if (cancellationToken.IsCancellationRequested)
            {
                _state = BehavioralRuntimeBindingState.Stopped;
                return Task.FromCanceled(cancellationToken);
            }

            _state = BehavioralRuntimeBindingState.Starting;

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

            if (_state is BehavioralRuntimeBindingState.Stopped
                or BehavioralRuntimeBindingState.Disabled
                or BehavioralRuntimeBindingState.Stopping)
            {
                // Idempotent — already stopped.
                if (_state == BehavioralRuntimeBindingState.Disabled && !_options.Enabled)
                    return Task.CompletedTask;
            }

            _state = BehavioralRuntimeBindingState.Stopping;

            if (_pipeline is not null && _subscribed)
            {
                _pipeline.Unsubscribe(this);
                _subscribed = false;
            }

            _correlation.Clear();
            _state = BehavioralRuntimeBindingState.Stopped;
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
            if (_disposed || !_options.Enabled) { _eventsDropped++; return ValueTask.CompletedTask; }
            if (_state is not (BehavioralRuntimeBindingState.Running
                or BehavioralRuntimeBindingState.Passive
                or BehavioralRuntimeBindingState.DevelopmentSafe
                or BehavioralRuntimeBindingState.Degraded))
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
                MarkDegraded("Behavioral runtime rate limit reached; some events were dropped.");
                return ValueTask.CompletedTask;
            }

            try
            {
                ProcessEvent(runtimeEvent, now);
            }
            catch (Exception ex)
            {
                AddWarning($"Event handling failed: {ex.GetType().Name}: {Trim(ex.Message)}");
            }
        }

        return ValueTask.CompletedTask;
    }

    public BehavioralRuntimeBindingStatus GetStatus()
    {
        lock (_gate)
        {
            return new BehavioralRuntimeBindingStatus
            {
                Enabled = _options.Enabled,
                PassiveMode = _options.PassiveMode,
                DevelopmentMode = _options.DevelopmentMode,
                State = _state,
                EventsReceived = _eventsReceived,
                ObservationsCreated = _observationsCreated,
                EvidenceGenerated = _evidenceGenerated,
                EventsDropped = _eventsDropped,
                TrackedProcesses = _correlation.Count,
                LastWarning = _warnings.Count == 0 ? null : _warnings.Last!.Value,
                LastEventUtc = _lastEventUtc,
            };
        }
    }

    /// <summary>Bounded snapshot of the most recent behavioral evidence (for tests/reporting).</summary>
    public IReadOnlyList<BehavioralRuntimeEvidence> GetRecentEvidence()
    {
        lock (_gate)
        {
            return _recentEvidence.Count == 0
                ? Array.Empty<BehavioralRuntimeEvidence>()
                : new List<BehavioralRuntimeEvidence>(_recentEvidence);
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
            _correlation.Clear();
            _recentEvidence.Clear();
            _disposed = true;
            _state = BehavioralRuntimeBindingState.Stopped;
        }
    }

    // ----- internals (all called under _gate) -------------------------------

    private void ProcessEvent(RuntimeSecurityEvent runtimeEvent, DateTimeOffset now)
    {
        var observation = _adapter.Map(runtimeEvent);
        if (observation is null) return;
        _observationsCreated++;

        // Update bounded, TTL-cleaned correlation state for process events.
        if (observation.ProcessId is int pid && pid > 0
            && observation.Kind is BehavioralObservationKind.ProcessStart
                or BehavioralObservationKind.CommandLine
                or BehavioralObservationKind.Script)
        {
            _correlation.Observe(
                pid,
                now,
                out var evicted,
                observation.ParentProcessId,
                observation.ProcessName,
                observation.ImagePath,
                observation.CommandLine);

            if (evicted)
            {
                _eventsDropped++;
                MarkDegraded("Runtime behavioral state limit reached; some events were dropped.");
            }
        }
        else
        {
            // Keep TTL cleanup moving even on non-process events.
            _correlation.Prune(now);
        }

        var evidenceList = _evaluator.Evaluate(observation, _correlation);
        if (evidenceList.Count == 0) return;

        foreach (var evidence in evidenceList)
        {
            _evidenceGenerated++;
            RetainEvidence(evidence);
            DispatchEvidence(evidence);
        }
    }

    private void DispatchEvidence(BehavioralRuntimeEvidence evidence)
    {
        // Passive observer notification only — never an action.
        if (_evidenceSink is not null)
        {
            try { _evidenceSink.OnEvidence(evidence); }
            catch (Exception ex) { AddWarning($"Evidence sink threw {ex.GetType().Name}: {Trim(ex.Message)}"); }
        }

        // Optional reporting telemetry. Off by default and guarded against
        // feedback loops: we publish a DetectionEvidence event sourced as
        // BehavioralEngine; HandleAsync only consumes process/command/
        // file/persistence/tamper categories, so it ignores this event.
        if (_options.RepublishEvidenceToPipeline && _pipeline is not null)
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

    private void RetainEvidence(BehavioralRuntimeEvidence evidence)
    {
        _recentEvidence.AddLast(evidence);
        while (_recentEvidence.Count > _options.MaxRetainedEvidence)
        {
            _recentEvidence.RemoveFirst();
        }
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

    private BehavioralRuntimeBindingState ResolveRunningState()
    {
        if (_degraded) return BehavioralRuntimeBindingState.Degraded;
        if (_options.PassiveMode) return BehavioralRuntimeBindingState.Passive;
        if (_options.DevelopmentMode) return BehavioralRuntimeBindingState.DevelopmentSafe;
        return BehavioralRuntimeBindingState.Running;
    }

    private void MarkDegraded(string warning)
    {
        _degraded = true;
        if (_state is BehavioralRuntimeBindingState.Running
            or BehavioralRuntimeBindingState.Passive
            or BehavioralRuntimeBindingState.DevelopmentSafe)
        {
            _state = BehavioralRuntimeBindingState.Degraded;
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
