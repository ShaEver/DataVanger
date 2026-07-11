using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Etw;

namespace DataVanger.Infrastructure.Etw;

/// <summary>
/// Safe no-op ETW runtime provider. Always reports
/// <see cref="EtwProviderStatus.Disabled"/> after construction and
/// <see cref="EtwProviderStatus.Stopped"/> after disposal.
///
/// This is the provider the factory returns when:
///   - the host OS is unsupported,
///   - configuration disables ETW,
///   - the real provider is not allowed (development/test mode), or
///   - the caller asks explicitly for a Null provider.
///
/// It never starts threads, never opens ETW sessions, never requires
/// admin privileges, and never publishes any events.
///
/// Anti-FP guarantee: zero events => zero verdicts.
/// </summary>
public sealed class NullEtwRuntimeProvider : IEtwRuntimeProvider
{
    private readonly EtwProviderStatus _initialStatus;
    private int _started;
    private int _disposed;
    private DateTimeOffset? _startedAtUtc;
    private DateTimeOffset? _stoppedAtUtc;

    public NullEtwRuntimeProvider(EtwProviderStatus initialStatus = EtwProviderStatus.Disabled)
    {
        _initialStatus = initialStatus;
        Status = initialStatus;
    }

    public string Name => "null-etw";

    public EtwProviderStatus Status { get; private set; }

    public EtwProviderHealth GetHealth() => new()
    {
        ProviderName = Name,
        Status = Status,
        StartedAtUtc = _startedAtUtc,
        StoppedAtUtc = _stoppedAtUtc,
        EventsPublished = 0,
        EventsDropped = 0,
        EventsFailed = 0,
        IsPlatformSupported = OperatingSystem.IsWindows(),
        IsRealProviderAllowed = false,
        IsDevelopmentMode = true,
        LastError = null,
    };

    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _disposed) == 1) return Task.CompletedTask;
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.Exchange(ref _started, 1) == 0)
        {
            _startedAtUtc = DateTimeOffset.UtcNow;
            // Null provider stays "Disabled" by design — it never
            // promotes to Running because it never collects events.
            Status = _initialStatus;
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

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            Status = EtwProviderStatus.Stopped;
            _stoppedAtUtc ??= DateTimeOffset.UtcNow;
        }
        return ValueTask.CompletedTask;
    }
}
