using System;
using DataVanger.Core;
using DataVanger.Core.Abstractions;

namespace DataVanger.Infrastructure;

/// <summary>
/// Adapter exposing <see cref="RealtimeMonitor"/> as <see cref="IRealtimeMonitorService"/>.
/// </summary>
public sealed class RealtimeMonitorServiceAdapter : IRealtimeMonitorService
{
    private readonly RealtimeMonitor _inner;

    public RealtimeMonitorServiceAdapter(RealtimeMonitor inner)
    {
        _inner = inner;
        _inner.SuspiciousFileCreated += path => SuspiciousFileCreated?.Invoke(path);
    }

    public bool IsRunning => _inner.IsRunning;
    public event Action<string>? SuspiciousFileCreated;

    public void Start() => _inner.Start();
    public void Stop() => _inner.Stop();
    public void Dispose() => _inner.Dispose();
}
