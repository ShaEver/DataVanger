using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using DataVanger.Shared.Etw;
using DataVanger.Shared.RuntimeEvents;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace DataVanger.Infrastructure.Etw;

/// <summary>
/// Windows-only ETW runtime provider introduced in Phase 2
/// Step 05 (ETW Real Provider).
///
/// The phase spec is clear:
///   "Do NOT implement kernel drivers, do NOT inject into processes,
///    do NOT hook low-level OS internals, do NOT require admin
///    privileges for tests."
///
/// To honor those constraints AND ship a real provider behind safe
/// gates, the class:
///   - confirms the host is Windows;
///   - confirms configuration allows the real provider;
///   - confirms we are not in development mode (unless the operator
///     explicitly opts in via
///     <see cref="EtwProviderConfiguration.ForceRealProviderInDevelopment"/>);
///   - opens a private TraceEvent session only after every gate passes;
///   - subscribes only to process lifecycle telemetry;
///   - normalizes observations through <see cref="EtwRuntimeEventMapper"/>;
///   - otherwise degrades to one of the safe states
///     (UnsupportedPlatform / NotConfigured / PermissionDenied /
///     ProviderUnavailable).
///
/// Anti-FP guarantee:
///   - Publishes only telemetry through the runtime event pipeline.
///   - Has NO quarantine, kill, block, or confirmation surface.
///   - Will never escalate an ETW observation into ConfirmedMalware.
/// </summary>
public sealed class WindowsEtwRuntimeProvider : IEtwRuntimeProvider
{
    private readonly IRuntimeEventPublisher _publisher;
    private readonly EtwProviderConfiguration _configuration;
    private readonly Func<bool>? _platformProbeOverride;
    private readonly object _rateGate = new();

    private int _started;
    private int _disposed;
    private DateTimeOffset? _startedAtUtc;
    private DateTimeOffset? _stoppedAtUtc;
    private string? _lastError;
    private long _eventsPublished;
    private long _eventsDropped;
    private long _eventsFailed;
    private long _rateWindowSecond;
    private int _rateWindowCount;

    private TraceEventSession? _session;
    private CancellationTokenSource? _sessionCancellation;
    private Channel<RuntimeSecurityEvent>? _eventChannel;
    private Task? _sessionTask;
    private Task? _publisherTask;

    public WindowsEtwRuntimeProvider(
        IRuntimeEventPublisher publisher,
        EtwProviderConfiguration? configuration = null,
        Func<bool>? platformProbeOverride = null)
    {
        _publisher = publisher ?? throw new ArgumentNullException(nameof(publisher));
        _configuration = (configuration ?? EtwProviderConfiguration.DevelopmentSafe()).WithSafeDefaults();
        _platformProbeOverride = platformProbeOverride;
        Status = EvaluateInitialStatus();
    }

    public string Name => "windows-etw";

    public EtwProviderStatus Status { get; private set; }

    public EtwProviderHealth GetHealth() => new()
    {
        ProviderName = Name,
        Status = Status,
        StartedAtUtc = _startedAtUtc,
        StoppedAtUtc = _stoppedAtUtc,
        EventsPublished = Interlocked.Read(ref _eventsPublished),
        EventsDropped = Interlocked.Read(ref _eventsDropped),
        EventsFailed = Interlocked.Read(ref _eventsFailed),
        IsPlatformSupported = IsPlatformSupported(),
        IsRealProviderAllowed = _configuration.AllowRealProvider,
        IsDevelopmentMode = _configuration.DevelopmentMode,
        LastError = _lastError,
    };

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _disposed) == 1) return;
        if (cancellationToken.IsCancellationRequested) return;

        if (Interlocked.Exchange(ref _started, 1) == 1)
        {
            // Idempotent: already started. Do not re-enter the activation path.
            return;
        }

        _startedAtUtc = DateTimeOffset.UtcNow;

        // Re-evaluate gating in case configuration changed between
        // construction and start (the constructor's status is just an
        // initial best-effort).
        var gate = EvaluateInitialStatus();
        if (gate != EtwProviderStatus.Starting)
        {
            Status = gate;
            await PublishHealthSafe(Status, $"Real ETW provider not activated: {gate}", cancellationToken).ConfigureAwait(false);
            return;
        }

        Status = EtwProviderStatus.Starting;
        try
        {
            var activated = TryActivateRealSession(out var failureStatus, out var activationError);
            if (activated)
            {
                Status = EtwProviderStatus.Running;
                await PublishHealthSafe(EtwProviderStatus.Running, "Windows ETW provider running.", cancellationToken).ConfigureAwait(false);
            }
            else
            {
                _lastError = activationError;
                Status = failureStatus;
                await PublishHealthSafe(failureStatus,
                    activationError ?? "Real ETW backend is not available in this build.",
                    cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            // Failures during activation must become a degraded
            // health state, never a thrown exception.
            _lastError = $"{ex.GetType().Name}: {Trim(ex.Message)}";
            Status = EtwProviderStatus.Faulted;
            await PublishHealthSafe(EtwProviderStatus.Faulted, _lastError, cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _disposed) == 1) return;
        await StopInternalAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            try { await StopInternalAsync(CancellationToken.None).ConfigureAwait(false); }
            catch { /* dispose never throws */ }
            Status = EtwProviderStatus.Stopped;
            _stoppedAtUtc ??= DateTimeOffset.UtcNow;
        }
    }

    private async Task StopInternalAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _started, 0) == 0)
        {
            await StopRealSessionAsync().ConfigureAwait(false);
            return;
        }

        await StopRealSessionAsync().ConfigureAwait(false);
        _stoppedAtUtc = DateTimeOffset.UtcNow;
        Status = EtwProviderStatus.Stopped;

        try
        {
            await PublishHealthSafe(EtwProviderStatus.Stopped, "Windows ETW provider stopped.", cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Stop never throws.
        }
    }

    /// <summary>
    /// Starts a private TraceEvent-backed process telemetry session.
    /// Kept private so callers cannot bypass the configuration and
    /// platform gates above.
    /// </summary>
    private bool TryActivateRealSession(out EtwProviderStatus failureStatus, out string? error)
    {
        failureStatus = EtwProviderStatus.ProviderUnavailable;
        error = null;

        // Use the same platform probe as the rest of the provider so the
        // activation path stays consistent with the construction/gating
        // path. In production the probe override is null and this collapses
        // to OperatingSystem.IsWindows(); the override only exists to make
        // graceful-degradation tests deterministic across host platforms.
        if (!IsPlatformSupported())
        {
            failureStatus = EtwProviderStatus.UnsupportedPlatform;
            error = "Windows ETW backend requires Windows.";
            return false;
        }

        if (!_configuration.CaptureProcessStart && !_configuration.CaptureCommandLine)
        {
            error = "Windows ETW backend has no enabled capture scopes.";
            return false;
        }

        try
        {
            var sessionName = $"DataVanger-ProcessEtw-{Environment.ProcessId}-{Guid.NewGuid():N}";
            _sessionCancellation = new CancellationTokenSource();
            _eventChannel = Channel.CreateBounded<RuntimeSecurityEvent>(new BoundedChannelOptions(_configuration.MaxQueueSize)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait,
            });

            _session = new TraceEventSession(sessionName)
            {
                StopOnDispose = true,
            };
            _session.Source.AllEvents += HandleTraceEvent;

            // Kernel process telemetry is the minimal initial scope for
            // process start events. If the host lacks permission,
            // TraceEvent throws here and we degrade without crashing.
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

            _publisherTask = Task.Run(
                () => PublishQueuedEventsAsync(_sessionCancellation.Token),
                CancellationToken.None);
            _sessionTask = Task.Factory.StartNew(
                ProcessTraceSourceSafe,
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
            return true;
        }
        catch (Exception ex)
        {
            failureStatus = IsPermissionDenied(ex)
                ? EtwProviderStatus.PermissionDenied
                : EtwProviderStatus.ProviderUnavailable;
            error = $"{ex.GetType().Name}: {Trim(ex.Message)}";
            StopRealSessionAsync().GetAwaiter().GetResult();
            return false;
        }
    }

    private void ProcessTraceSourceSafe()
    {
        try
        {
            _session?.Source.Process();
        }
        catch (Exception ex) when (!IsStopping())
        {
            Interlocked.Increment(ref _eventsFailed);
            _lastError = $"{ex.GetType().Name}: {Trim(ex.Message)}";
            if (Status == EtwProviderStatus.Running)
            {
                Status = EtwProviderStatus.Degraded;
            }
        }
        finally
        {
            try { _eventChannel?.Writer.TryComplete(); } catch (Exception) { /* Dispose/Stop may throw on already-disposed or never-started instances - ignore. */ }
        }
    }

    private async Task StopRealSessionAsync()
    {
        var cancellation = _sessionCancellation;
        var session = _session;
        var channel = _eventChannel;
        var sessionTask = _sessionTask;
        var publisherTask = _publisherTask;

        _session = null;
        _eventChannel = null;
        _sessionTask = null;
        _publisherTask = null;
        _sessionCancellation = null;

        try { cancellation?.Cancel(); } catch (Exception) { /* Dispose/Stop may throw on already-disposed or never-started instances - ignore. */ }
        try { session?.Source.StopProcessing(); } catch (Exception) { /* Dispose/Stop may throw on already-disposed or never-started instances - ignore. */ }
        try { session?.Dispose(); } catch (Exception) { /* Dispose/Stop may throw on already-disposed or never-started instances - ignore. */ }
        try { channel?.Writer.TryComplete(); } catch (Exception) { /* Dispose/Stop may throw on already-disposed or never-started instances - ignore. */ }

        await WaitBriefly(sessionTask).ConfigureAwait(false);
        await WaitBriefly(publisherTask).ConfigureAwait(false);

        try { cancellation?.Dispose(); } catch (Exception) { /* Dispose/Stop may throw on already-disposed or never-started instances - ignore. */ }
    }

    private static async Task WaitBriefly(Task? task)
    {
        if (task is null || task.IsCompleted) return;
        try { await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false); }
        catch (Exception) { /* Dispose/Stop may throw on already-disposed or never-started instances - ignore. */ }
    }

    private async Task PublishQueuedEventsAsync(CancellationToken cancellationToken)
    {
        var reader = _eventChannel?.Reader;
        if (reader is null) return;

        try
        {
            await foreach (var ev in reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
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
                    _lastError = $"{ex.GetType().Name}: {Trim(ex.Message)}";
                    if (Status == EtwProviderStatus.Running)
                    {
                        Status = EtwProviderStatus.Degraded;
                    }
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Cooperative shutdown.
        }
    }

    private void HandleTraceEvent(TraceEvent data)
    {
        if (data is null || IsStopping()) return;
        if (!LooksLikeProcessStart(data)) return;

        var processId = PayloadInt(data, "ProcessID", "ProcessId", "PID") ?? data.ProcessID;
        if (processId <= 0)
        {
            Interlocked.Increment(ref _eventsDropped);
            return;
        }

        var imagePath = PayloadString(data, "ImageFileName", "ImageName", "ImagePath");
        var commandLine = PayloadString(data, "CommandLine", "Command line");
        var processName = PayloadString(data, "ProcessName")
            ?? SafeFileName(imagePath)
            ?? data.ProcessName;
        var timestamp = data.TimeStamp == default
            ? DateTimeOffset.UtcNow
            : new DateTimeOffset(data.TimeStamp.ToUniversalTime());

        RuntimeSecurityEvent? ev = null;
        if (_configuration.CaptureProcessStart)
        {
            ev = EtwRuntimeEventMapper.MapProcessStart(new EtwProcessStartObservation
            {
                ProcessId = processId,
                ParentProcessId = PayloadInt(data, "ParentID", "ParentId", "ParentProcessID", "ParentProcessId"),
                ProcessName = processName,
                ImagePath = imagePath,
                CommandLine = commandLine,
                TimestampUtc = timestamp,
                RawProviderName = data.ProviderName,
                RawEventName = data.EventName,
            }, _configuration);
        }
        else if (_configuration.CaptureCommandLine && !string.IsNullOrEmpty(commandLine))
        {
            ev = EtwRuntimeEventMapper.MapCommandLine(new EtwCommandLineObservation
            {
                ProcessId = processId,
                ProcessName = processName,
                CommandLine = commandLine!,
                TimestampUtc = timestamp,
                RawProviderName = data.ProviderName,
                RawEventName = data.EventName,
            }, _configuration);
        }

        if (ev is null)
        {
            Interlocked.Increment(ref _eventsDropped);
            return;
        }

        TryQueue(ev);
    }

    private void TryQueue(RuntimeSecurityEvent ev)
    {
        if (!AllowByRateLimit())
        {
            Interlocked.Increment(ref _eventsDropped);
            return;
        }

        var writer = _eventChannel?.Writer;
        if (writer is null || !writer.TryWrite(ev))
        {
            Interlocked.Increment(ref _eventsDropped);
        }
    }

    private bool AllowByRateLimit()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        lock (_rateGate)
        {
            if (_rateWindowSecond != now)
            {
                _rateWindowSecond = now;
                _rateWindowCount = 0;
            }

            if (_rateWindowCount >= _configuration.MaxEventsPerSecond)
            {
                return false;
            }

            _rateWindowCount++;
            return true;
        }
    }

    private EtwProviderStatus EvaluateInitialStatus()
    {
        if (!_configuration.Enabled)
        {
            return EtwProviderStatus.Disabled;
        }
        if (!IsPlatformSupported())
        {
            return EtwProviderStatus.UnsupportedPlatform;
        }
        if (!_configuration.AllowRealProvider)
        {
            return EtwProviderStatus.NotConfigured;
        }
        if (_configuration.DevelopmentMode && !_configuration.ForceRealProviderInDevelopment)
        {
            return EtwProviderStatus.NotConfigured;
        }
        return EtwProviderStatus.Starting;
    }

    private bool IsPlatformSupported()
        => _platformProbeOverride?.Invoke() ?? OperatingSystem.IsWindows();

    private bool IsStopping()
        => Volatile.Read(ref _disposed) == 1
           || Volatile.Read(ref _started) == 0
           || _sessionCancellation?.IsCancellationRequested == true;

    private static bool LooksLikeProcessStart(TraceEvent data)
    {
        var name = data.EventName ?? string.Empty;
        return name.IndexOf("Process", StringComparison.OrdinalIgnoreCase) >= 0
            && name.IndexOf("Start", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static string? PayloadString(TraceEvent data, params string[] names)
    {
        foreach (var name in names)
        {
            try
            {
                var value = data.PayloadByName(name);
                if (value is null) continue;
                var text = Convert.ToString(value);
                if (!string.IsNullOrWhiteSpace(text)) return text;
            }
            catch
            {
                // Payload schemas differ by provider/version.
            }
        }
        return null;
    }

    private static int? PayloadInt(TraceEvent data, params string[] names)
    {
        foreach (var name in names)
        {
            try
            {
                var value = data.PayloadByName(name);
                if (value is null) continue;
                if (value is int i) return i;
                if (value is uint ui && ui <= int.MaxValue) return (int)ui;
                if (value is long l && l <= int.MaxValue && l >= int.MinValue) return (int)l;
                if (int.TryParse(Convert.ToString(value), out var parsed)) return parsed;
            }
            catch
            {
                // Payload schemas differ by provider/version.
            }
        }
        return null;
    }

    private static string? SafeFileName(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        try { return Path.GetFileName(path); }
        catch { return null; }
    }

    private static bool IsPermissionDenied(Exception ex)
    {
        if (ex is UnauthorizedAccessException) return true;
        if (ex is COMException { HResult: unchecked((int)0x80070005) }) return true;
        if (ex.HResult == unchecked((int)0x80070005)) return true;
        var message = ex.Message ?? string.Empty;
        return message.IndexOf("access", StringComparison.OrdinalIgnoreCase) >= 0
            || message.IndexOf("denied", StringComparison.OrdinalIgnoreCase) >= 0
            || message.IndexOf("admin", StringComparison.OrdinalIgnoreCase) >= 0
            || message.IndexOf("elevat", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private async ValueTask PublishHealthSafe(EtwProviderStatus status, string? message, CancellationToken cancellationToken)
    {
        try
        {
            var ev = EtwRuntimeEventMapper.MapHealth(Name, status, message);
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
            _lastError = $"{ex.GetType().Name}: {Trim(ex.Message)}";
        }
    }

    private static string Trim(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        const int max = 240;
        return value!.Length <= max ? value : value.Substring(0, max) + "...";
    }
}
