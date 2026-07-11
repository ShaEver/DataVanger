using System;

namespace DataVanger.Behavioral.Adapters;

/// <summary>
/// Placeholder for a future ETW-backed behavior provider.
///
/// The shape is intentionally minimal — a real implementation will
/// subscribe to <c>Microsoft-Windows-Kernel-Process</c>,
/// <c>Microsoft-Windows-PowerShell</c>, etc., translate sessions into
/// <see cref="BehavioralEvent"/> instances and publish them through the
/// engine's bus.
///
/// Today the class only documents the integration seam: it does not
/// open any ETW sessions, so it cannot leak handles or destabilise the
/// host. Tests verify that <see cref="Start"/> and <see cref="Dispose"/>
/// are no-ops.
/// </summary>
public sealed class EtwBehaviorProvider : IDisposable
{
    private readonly IBehavioralEventBus _bus;
    public bool IsRunning { get; private set; }
    public bool IsAvailable => false; // No real ETW session in this build.

    public EtwBehaviorProvider(IBehavioralEventBus bus)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
    }

    public void Start()
    {
        // No-op. Future: open ETW session, hook into TraceEventParser.
        IsRunning = false;
    }

    public void Dispose()
    {
        IsRunning = false;
    }
}
