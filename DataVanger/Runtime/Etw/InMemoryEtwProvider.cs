using System;
using System.Collections.Generic;
using System.Threading;

namespace DataVanger.Runtime.Etw;

/// <summary>
/// Test-friendly ETW provider that replays explicitly supplied events.
///
/// Real ETW subscription requires admin privileges and is not available
/// in the test harness. This provider lets us exercise the rest of the
/// pipeline (bridge, throttle, behavioral integration) deterministically
/// without touching the OS. Production code uses
/// <see cref="EtwProviderFactory.Create"/> which will only ever return
/// this one when explicitly asked.
/// </summary>
public sealed class InMemoryEtwProvider : IEtwTelemetryProvider
{
    private int _started;
    private int _disposed;

    public string Name => "memory-etw";
    public RuntimeProviderState State { get; private set; } = RuntimeProviderState.NotStarted;
    public bool IsRunning => Volatile.Read(ref _started) == 1 && Volatile.Read(ref _disposed) == 0;
    /// <summary>The in-memory provider is always "supported" — it never touches the OS.</summary>
    public bool IsHostSupported => true;

    public event Action<RuntimeTelemetryEvent>? EventReceived;

    public RuntimeProviderState Start()
    {
        if (Interlocked.Exchange(ref _started, 1) == 0)
            State = RuntimeProviderState.RunningMock;
        return State;
    }

    public void Stop()
    {
        if (Interlocked.Exchange(ref _started, 0) == 1)
            State = RuntimeProviderState.Stopped;
    }

    /// <summary>Inject a synthetic ETW event. No-op if the provider is stopped/disposed.</summary>
    public bool Emit(RuntimeTelemetryEvent ev)
    {
        if (ev is null) return false;
        if (!IsRunning) return false;
        var handler = EventReceived;
        if (handler is null) return false;
        try { handler(ev); }
        catch (System.Exception) { /* never break the publisher because a subscriber threw */ }
        return true;
    }

    /// <summary>Convenience: emit a process-start event.</summary>
    public bool EmitProcessStart(int pid, int parentPid, string processName, string imagePath, string commandLine)
        => Emit(new RuntimeTelemetryEvent(
            kind: RuntimeTelemetryEventKind.ProcessStart,
            providerName: Name,
            pid: pid, parentPid: parentPid,
            processName: processName ?? "", imagePath: imagePath ?? "",
            commandLine: commandLine ?? "", scriptContent: null,
            extraTag: "etw",
            timestampUtc: DateTime.UtcNow));

    public bool EmitProcessEnd(int pid, string processName)
        => Emit(new RuntimeTelemetryEvent(
            kind: RuntimeTelemetryEventKind.ProcessEnd,
            providerName: Name,
            pid: pid, parentPid: 0,
            processName: processName ?? "", imagePath: "",
            commandLine: "", scriptContent: null,
            extraTag: "etw",
            timestampUtc: DateTime.UtcNow));

    public bool EmitImageLoad(int pid, string processName, string imagePath)
        => Emit(new RuntimeTelemetryEvent(
            kind: RuntimeTelemetryEventKind.ImageLoad,
            providerName: Name,
            pid: pid, parentPid: 0,
            processName: processName ?? "", imagePath: imagePath ?? "",
            commandLine: "", scriptContent: null,
            extraTag: "etw",
            timestampUtc: DateTime.UtcNow));

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            Stop();
            EventReceived = null;
        }
    }
}
