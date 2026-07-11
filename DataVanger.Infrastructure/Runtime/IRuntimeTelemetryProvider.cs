using System;

namespace DataVanger.Runtime;

/// <summary>
/// Common contract for runtime telemetry providers (ETW, AMSI, future
/// sources). The interface is intentionally minimal so adapters and
/// no-op providers can satisfy it without dragging in OS dependencies.
///
/// Contract:
///   - <see cref="Start"/> MUST be safe to call even on unsupported
///     environments. Failures become a state change, never an exception
///     that crashes the host.
///   - <see cref="EventReceived"/> handlers MUST be called on a worker
///     thread; the provider must never invoke them while holding
///     internal locks. Handlers themselves are expected to be fast.
///   - <see cref="Dispose"/> MUST be idempotent and never throw.
/// </summary>
public interface IRuntimeTelemetryProvider : IDisposable
{
    /// <summary>Friendly name (e.g. "etw-process", "amsi", "mock-etw").</summary>
    string Name { get; }

    /// <summary>Current lifecycle state.</summary>
    RuntimeProviderState State { get; }

    /// <summary>True when the provider has been able to emit at least one real event.</summary>
    bool IsRunning { get; }

    /// <summary>Try to start the provider. Returns the post-start state.</summary>
    RuntimeProviderState Start();

    /// <summary>Stop the provider. Idempotent.</summary>
    void Stop();

    /// <summary>
    /// Raised for every normalized telemetry event. The handler must be
    /// thread-safe — providers may publish concurrently.
    /// </summary>
    event Action<RuntimeTelemetryEvent>? EventReceived;
}
