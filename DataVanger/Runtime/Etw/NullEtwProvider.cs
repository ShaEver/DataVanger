using System;

namespace DataVanger.Runtime.Etw;

/// <summary>
/// Safe ETW provider that always reports unavailable.
///
/// Used when the host cannot subscribe to ETW (non-Windows, missing
/// privileges, future Windows hardening, etc). The interface stays
/// stable so the rest of the runtime pipeline keeps working — it just
/// never receives events. This is the "graceful degradation" path
/// referenced in the spec.
/// </summary>
public sealed class NullEtwProvider : IEtwTelemetryProvider
{
    public string Name => "null-etw";
    public RuntimeProviderState State { get; private set; } = RuntimeProviderState.NotStarted;
    public bool IsRunning => false;
    public bool IsHostSupported => false;

    // Event is part of the interface contract — never raised here so callers can
    // still subscribe symmetrically with other providers without special-casing.
#pragma warning disable CS0067
    public event Action<RuntimeTelemetryEvent>? EventReceived;
#pragma warning restore CS0067

    public RuntimeProviderState Start()
    {
        State = RuntimeProviderState.Unavailable;
        return State;
    }

    public void Stop()
    {
        if (State == RuntimeProviderState.NotStarted) return;
        State = RuntimeProviderState.Stopped;
    }

    public void Dispose() => Stop();
}
