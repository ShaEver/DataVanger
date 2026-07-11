using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Etw;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Infrastructure.Etw;

/// <summary>
/// Deterministic, in-memory ETW runtime provider for tests and for
/// non-Windows hosts that want to exercise the full mapping +
/// publishing pipeline without touching the OS.
///
/// Producers call <see cref="EmitProcessStart"/> /
/// <see cref="EmitCommandLine"/> to inject synthetic observations.
/// The provider runs them through <see cref="EtwRuntimeEventMapper"/>
/// and publishes the result through the supplied
/// <see cref="IRuntimeEventPublisher"/>.
///
/// Lifecycle:
///   - Construction does NOT subscribe to anything.
///   - <see cref="StartAsync"/> flips status to Running and is idempotent.
///   - <see cref="StopAsync"/> flips status to Stopped and is idempotent.
///   - After StopAsync (or Dispose) emissions become no-ops counted as dropped.
///
/// Safety guarantees:
///   - No background loops, no threads, no timers.
///   - All work happens on the publishing thread.
///   - Cancellation is honored.
///   - Disposal NEVER hangs.
///   - Never mutates classification or quarantine state.
/// </summary>
public sealed class InMemoryEtwRuntimeProvider : IEtwRuntimeProvider
{
    private readonly IRuntimeEventPublisher _publisher;
    private readonly EtwProviderConfiguration _configuration;
    private readonly object _gate = new();
    private readonly LinkedList<string> _warnings = new();

    private int _started;
    private int _disposed;
    private long _eventsPublished;
    private long _eventsDropped;
    private long _eventsFailed;
    private DateTimeOffset? _startedAtUtc;
    private DateTimeOffset? _stoppedAtUtc;
    private string? _lastError;

    public InMemoryEtwRuntimeProvider(IRuntimeEventPublisher publisher, EtwProviderConfiguration? configuration = null)
    {
        _publisher = publisher ?? throw new ArgumentNullException(nameof(publisher));
        _configuration = (configuration ?? EtwProviderConfiguration.InMemoryForTests()).WithSafeDefaults();
        Status = _configuration.Enabled ? EtwProviderStatus.NotConfigured : EtwProviderStatus.Disabled;
    }

    public string Name => "in-memory-etw";

    public EtwProviderStatus Status { get; private set; }

    public EtwProviderHealth GetHealth()
    {
        string[] warnings;
        lock (_gate)
        {
            warnings = _warnings.Count == 0 ? Array.Empty<string>() : _warnings.ToArray();
        }

        return new EtwProviderHealth
        {
            ProviderName = Name,
            Status = Status,
            StartedAtUtc = _startedAtUtc,
            StoppedAtUtc = _stoppedAtUtc,
            EventsPublished = Interlocked.Read(ref _eventsPublished),
            EventsDropped = Interlocked.Read(ref _eventsDropped),
            EventsFailed = Interlocked.Read(ref _eventsFailed),
            IsPlatformSupported = true, // in-memory never touches the OS
            IsRealProviderAllowed = _configuration.AllowRealProvider,
            IsDevelopmentMode = _configuration.DevelopmentMode,
            LastError = _lastError,
            Warnings = warnings,
        };
    }

    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _disposed) == 1) return Task.CompletedTask;
        cancellationToken.ThrowIfCancellationRequested();

        if (Interlocked.Exchange(ref _started, 1) == 0)
        {
            _startedAtUtc = DateTimeOffset.UtcNow;
            Status = _configuration.Enabled
                ? EtwProviderStatus.Running
                : EtwProviderStatus.Disabled;
        }
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _disposed) == 1) return Task.CompletedTask;
        if (Interlocked.Exchange(ref _started, 0) == 1)
        {
            _stoppedAtUtc = DateTimeOffset.UtcNow;
            Status = EtwProviderStatus.Stopped;
        }
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            try { await StopAsync(CancellationToken.None).ConfigureAwait(false); }
            catch (System.Exception) { /* dispose never throws */ }
            Status = EtwProviderStatus.Stopped;
            _stoppedAtUtc ??= DateTimeOffset.UtcNow;
        }
    }

    /// <summary>
    /// Inject a synthetic process-start observation. No-op (counted as
    /// dropped) when stopped, disposed, disabled, or rate-limited.
    /// </summary>
    public async ValueTask EmitProcessStart(EtwProcessStartObservation observation, CancellationToken cancellationToken = default)
    {
        if (!IsRunningForEmit())
        {
            Interlocked.Increment(ref _eventsDropped);
            return;
        }
        if (observation is null)
        {
            Interlocked.Increment(ref _eventsDropped);
            return;
        }
        if (!_configuration.CaptureProcessStart)
        {
            Interlocked.Increment(ref _eventsDropped);
            return;
        }

        var ev = EtwRuntimeEventMapper.MapProcessStart(observation, _configuration);
        await PublishMappedEvent(ev, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Inject a synthetic command-line observation. No-op (counted as
    /// dropped) when stopped, disposed, disabled, or rate-limited.
    /// </summary>
    public async ValueTask EmitCommandLine(EtwCommandLineObservation observation, CancellationToken cancellationToken = default)
    {
        if (!IsRunningForEmit())
        {
            Interlocked.Increment(ref _eventsDropped);
            return;
        }
        if (observation is null)
        {
            Interlocked.Increment(ref _eventsDropped);
            return;
        }
        if (!_configuration.CaptureCommandLine)
        {
            Interlocked.Increment(ref _eventsDropped);
            return;
        }

        var ev = EtwRuntimeEventMapper.MapCommandLine(observation, _configuration);
        await PublishMappedEvent(ev, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Publish a synthetic health event (e.g. for tests that want to
    /// observe how the runtime pipeline routes ETW health into
    /// existing consumers). Always allowed when the provider is
    /// constructed; not gated by capture flags.
    /// </summary>
    public ValueTask EmitHealth(EtwProviderStatus status, string? message = null, CancellationToken cancellationToken = default)
    {
        var ev = EtwRuntimeEventMapper.MapHealth(Name, status, message);
        return PublishMappedEvent(ev, cancellationToken);
    }

    private bool IsRunningForEmit()
    {
        if (Volatile.Read(ref _disposed) == 1) return false;
        if (Volatile.Read(ref _started) == 0) return false;
        if (!_configuration.Enabled) return false;
        if (Status != EtwProviderStatus.Running) return false;
        return true;
    }

    private async ValueTask PublishMappedEvent(RuntimeSecurityEvent? ev, CancellationToken cancellationToken)
    {
        if (ev is null)
        {
            Interlocked.Increment(ref _eventsDropped);
            return;
        }
        try
        {
            await _publisher.PublishAsync(ev, cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref _eventsPublished);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Interlocked.Increment(ref _eventsDropped);
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _eventsFailed);
            RecordWarning($"Publish failed: {ex.GetType().Name}: {Trim(ex.Message)}");
        }
    }

    private void RecordWarning(string warning)
    {
        if (string.IsNullOrWhiteSpace(warning)) return;
        lock (_gate)
        {
            _lastError = warning;
            _warnings.AddLast(warning);
            while (_warnings.Count > 64) _warnings.RemoveFirst();
        }
    }

    private static string Trim(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        const int max = 240;
        return value!.Length <= max ? value : value.Substring(0, max) + "...";
    }
}
