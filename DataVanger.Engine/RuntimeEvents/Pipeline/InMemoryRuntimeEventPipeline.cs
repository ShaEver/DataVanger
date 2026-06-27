using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Engine.RuntimeEvents;

/// <summary>
/// Deterministic in-memory implementation of <see cref="IRuntimeEventPipeline"/>
/// introduced in Phase 2 Step 04 (Runtime Event Pipeline).
///
/// Design choices (all of which exist to satisfy the development-mode
/// safety and anti-FP constraints of this phase):
///
///   - Inline dispatch on the publishing thread. There are no
///     background loops, no Channel readers, no Tasks spawned per
///     event, no Timers, no Threads. Tests are fully deterministic
///     without sleeps.
///
///   - Bounded by an in-flight depth counter against
///     <see cref="RuntimeEventPipelineOptions.MaxQueueSize"/>. When the
///     limit would be exceeded, the incoming event is dropped per the
///     configured <see cref="RuntimeEventDropPolicy"/> and counted.
///     Memory growth is therefore strictly bounded.
///
///   - Consumer failures are isolated. A throwing consumer increments
///     the warning buffer (bounded by
///     <see cref="RuntimeEventPipelineOptions.MaxRetainedWarnings"/>)
///     and does NOT abort delivery to the remaining consumers; it does
///     NOT crash the pipeline.
///
///   - The pipeline is NOT a classifier. A published event NEVER
///     becomes ConfirmedMalware, NEVER quarantines, NEVER kills a
///     process, NEVER blocks a file. It is telemetry infrastructure.
///
///   - Disposed pipelines drop further publishes silently (counted) so
///     producers racing with shutdown do not throw.
/// </summary>
public sealed class InMemoryRuntimeEventPipeline : IRuntimeEventPipeline
{
    private readonly RuntimeEventPipelineOptions _options;
    private readonly object _gate = new();
    private readonly List<IRuntimeEventConsumer> _consumers = new();
    private readonly LinkedList<string> _warnings = new();

    private long _eventsPublished;
    private long _eventsDelivered;
    private long _eventsDropped;
    private int _queueDepth;
    private int _maxQueueDepth;
    private bool _disposed;

    public InMemoryRuntimeEventPipeline()
        : this(RuntimeEventPipelineOptions.DevelopmentSafe())
    {
    }

    public InMemoryRuntimeEventPipeline(RuntimeEventPipelineOptions options)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));
        _options = options.WithSafeDefaults();
    }

    public void Subscribe(IRuntimeEventConsumer consumer)
    {
        if (consumer is null) throw new ArgumentNullException(nameof(consumer));
        lock (_gate)
        {
            if (_disposed) return;
            if (_consumers.Contains(consumer))
            {
                // Idempotent: never double-deliver to the same instance.
                return;
            }
            _consumers.Add(consumer);
        }
    }

    public bool Unsubscribe(IRuntimeEventConsumer consumer)
    {
        if (consumer is null) return false;
        lock (_gate)
        {
            return _consumers.Remove(consumer);
        }
    }

    public async ValueTask PublishAsync(RuntimeSecurityEvent runtimeEvent, CancellationToken cancellationToken = default)
    {
        if (runtimeEvent is null)
        {
            // Treat as a dropped event so producers cannot quietly
            // produce nulls without showing up in diagnostics.
            Interlocked.Increment(ref _eventsDropped);
            return;
        }

        if (Volatile.Read(ref _disposed))
        {
            Interlocked.Increment(ref _eventsDropped);
            return;
        }

        if (!_options.Enabled || _options.Mode == RuntimeEventPipelineMode.Disabled)
        {
            // Disabled mode never delivers — but it still counts dropped
            // events so the health snapshot remains honest.
            Interlocked.Increment(ref _eventsDropped);
            return;
        }

        if (cancellationToken.IsCancellationRequested)
        {
            Interlocked.Increment(ref _eventsDropped);
            return;
        }

        // Backpressure: bound the in-flight count to MaxQueueSize.
        var depth = Interlocked.Increment(ref _queueDepth);
        try
        {
            if (depth > _options.MaxQueueSize)
            {
                // Drop per policy. DropLowestSeverityFirst behaves the
                // same as DropNewest in inline-dispatch mode because we
                // have no queued events to evict — but informational
                // events are dropped silently while higher-severity
                // overflows surface a warning so operators can react.
                Interlocked.Increment(ref _eventsDropped);
                if (_options.DropPolicy == RuntimeEventDropPolicy.DropLowestSeverityFirst
                    && runtimeEvent.Severity > RuntimeEventSeverity.Informational)
                {
                    AddWarning($"Pipeline queue full (depth={depth} > max={_options.MaxQueueSize}); dropped {runtimeEvent.Severity} event '{runtimeEvent.Title}'.");
                }
                else if (_options.DropPolicy == RuntimeEventDropPolicy.DropNewest
                         && runtimeEvent.Severity >= RuntimeEventSeverity.High)
                {
                    AddWarning($"Pipeline queue full (depth={depth} > max={_options.MaxQueueSize}); dropped {runtimeEvent.Severity} event '{runtimeEvent.Title}'.");
                }
                return;
            }

            // Track max observed depth without a lock.
            while (true)
            {
                var current = Volatile.Read(ref _maxQueueDepth);
                if (depth <= current) break;
                if (Interlocked.CompareExchange(ref _maxQueueDepth, depth, current) == current) break;
            }

            Interlocked.Increment(ref _eventsPublished);

            IRuntimeEventConsumer[] snapshot;
            lock (_gate)
            {
                if (_disposed)
                {
                    // Race with Dispose — count as dropped and exit.
                    Interlocked.Decrement(ref _eventsPublished);
                    Interlocked.Increment(ref _eventsDropped);
                    return;
                }
                snapshot = _consumers.ToArray();
            }

            foreach (var consumer in snapshot)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    // Honor cancellation: do not throw, simply stop
                    // delivering to remaining consumers.
                    break;
                }

                try
                {
                    await consumer.HandleAsync(runtimeEvent, cancellationToken).ConfigureAwait(false);
                    Interlocked.Increment(ref _eventsDelivered);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    // Cancellation is cooperative, not a failure — stop
                    // delivery to remaining consumers and return.
                    break;
                }
                catch (Exception ex)
                {
                    AddWarning($"Consumer '{SafeTypeName(consumer)}' threw {ex.GetType().Name}: {Trim(ex.Message)}");
                }
            }
        }
        finally
        {
            Interlocked.Decrement(ref _queueDepth);
        }
    }

    public RuntimeEventPipelineHealth GetHealthSnapshot()
    {
        int subscriberCount;
        string[] warnings;
        bool disposed;
        lock (_gate)
        {
            subscriberCount = _consumers.Count;
            warnings = _warnings.Count == 0 ? Array.Empty<string>() : _warnings.ToArray();
            disposed = _disposed;
        }

        var enabled = _options.Enabled && _options.Mode != RuntimeEventPipelineMode.Disabled && !disposed;
        var status = disposed
            ? "Stopped"
            : !enabled
                ? "Disabled"
                : warnings.Length == 0
                    ? "Healthy"
                    : "Degraded";

        return new RuntimeEventPipelineHealth
        {
            IsEnabled = enabled,
            IsDevelopmentMode = _options.Mode == RuntimeEventPipelineMode.Development,
            Mode = _options.Mode,
            SubscriberCount = subscriberCount,
            EventsPublished = Interlocked.Read(ref _eventsPublished),
            EventsDelivered = Interlocked.Read(ref _eventsDelivered),
            EventsDropped = Interlocked.Read(ref _eventsDropped),
            QueueDepth = Volatile.Read(ref _queueDepth),
            MaxQueueDepth = Volatile.Read(ref _maxQueueDepth),
            MaxQueueSize = _options.MaxQueueSize,
            Status = status,
            Warnings = warnings,
        };
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _consumers.Clear();
            // Warnings are intentionally retained so a post-shutdown
            // health snapshot still reflects what went wrong before
            // disposal.
        }
    }

    private void AddWarning(string warning)
    {
        if (!_options.EnableDevelopmentDiagnostics) return;
        if (string.IsNullOrWhiteSpace(warning)) return;

        lock (_gate)
        {
            _warnings.AddLast(warning);
            while (_warnings.Count > _options.MaxRetainedWarnings)
            {
                _warnings.RemoveFirst();
            }
        }
    }

    private static string SafeTypeName(IRuntimeEventConsumer consumer)
    {
        try { return consumer.GetType().FullName ?? consumer.GetType().Name; }
        catch (System.Exception) { return "<consumer>"; }
    }

    private static string Trim(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        const int max = 240;
        return value.Length <= max ? value : value.Substring(0, max) + "...";
    }
}
