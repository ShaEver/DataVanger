using System;
using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Cooperative throttle combining a concurrency semaphore and an optional
/// post-work CPU yield. Used by every worker entering an expensive stage
/// (hashing, content analysis, archive walk) so the deep pipeline cannot
/// saturate the host machine.
///
/// The throttle is reusable across stages: each stage holds a lease only
/// for the duration of its work, then releases it; failure to release is
/// guarded by <c>using</c> on <see cref="ScanLease"/>.
/// </summary>
public sealed class ScanThrottle : IDisposable
{
    private readonly SemaphoreSlim _semaphore;
    private readonly int _cpuYieldMs;
    private bool _disposed;

    public ScanThrottle(int maxConcurrency, int cpuYieldMs)
    {
        if (maxConcurrency <= 0) throw new ArgumentOutOfRangeException(nameof(maxConcurrency));
        _semaphore  = new SemaphoreSlim(maxConcurrency, maxConcurrency);
        _cpuYieldMs = Math.Max(0, cpuYieldMs);
    }

    public int CurrentCount => _semaphore.CurrentCount;

    /// <summary>Awaits a concurrency slot; release it by disposing the returned <see cref="ScanLease"/>.</summary>
    public async ValueTask<ScanLease> AcquireAsync(CancellationToken cancellationToken)
    {
        await _semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        return new ScanLease(this);
    }

    internal void Release()
    {
        try { _semaphore.Release(); } catch (ObjectDisposedException) { }
    }

    /// <summary>Optional cooperative pause; honoured between work items.</summary>
    public ValueTask YieldIfThrottledAsync(CancellationToken cancellationToken)
    {
        if (_cpuYieldMs <= 0) return ValueTask.CompletedTask;
        return new ValueTask(Task.Delay(_cpuYieldMs, cancellationToken));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _semaphore.Dispose();
    }
}

/// <summary>RAII lease returned by <see cref="ScanThrottle.AcquireAsync"/>.</summary>
public readonly struct ScanLease : IDisposable
{
    private readonly ScanThrottle? _owner;
    internal ScanLease(ScanThrottle owner) { _owner = owner; }
    public void Dispose() => _owner?.Release();
}
