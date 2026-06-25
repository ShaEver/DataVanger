using System;
using System.Threading;

namespace DataVanger.Runtime.Amsi;

/// <summary>
/// Test-friendly AMSI provider. <see cref="SubmitContent"/> runs the
/// content through <see cref="AmsiContentAnalyzer"/> and
/// <see cref="AmsiBypassDetector"/>, then emits one telemetry event
/// per finding kind (scan, bypass).
///
/// Used in tests and as a fallback path for callers that want AMSI-like
/// analysis on script samples they obtained through other means (e.g.
/// disk scan of a .ps1, intercepted clipboard paste, etc.).
/// </summary>
public sealed class InMemoryAmsiProvider : IAmsiTelemetryProvider
{
    private int _started;
    private int _disposed;

    public string Name => "memory-amsi";
    public RuntimeProviderState State { get; private set; } = RuntimeProviderState.NotStarted;
    public bool IsRunning => Volatile.Read(ref _started) == 1 && Volatile.Read(ref _disposed) == 0;
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

    public int SubmitContent(string source, string scriptContent, int pid)
    {
        if (!IsRunning) return 0;
        if (string.IsNullOrWhiteSpace(scriptContent)) return 0;
        var handler = EventReceived;
        if (handler is null) return 0;

        int published = 0;
        var bypassReasons = AmsiBypassDetector.Detect(scriptContent);
        if (bypassReasons.Count > 0)
        {
            published += Publish(handler, RuntimeTelemetryEventKind.AmsiBypassIndicator,
                source, scriptContent, pid, "amsi-bypass");
        }

        var content = AmsiContentAnalyzer.Analyze(source, scriptContent);
        // Surface a generic AmsiScan event when there is at least one
        // suspicious content tag. Benign scripts produce zero events.
        bool suspicious =
            content.HasTag("encoded-payload") ||
            content.HasTag("reflective-load") ||
            content.HasTag("base64-invoke") ||
            content.HasTag("download-cradle") ||
            content.HasTag("security-tamper") ||
            content.HasTag("obfuscation") ||
            content.HasTag("dynamic-execution") ||
            content.HasTag("long-base64");

        if (suspicious)
        {
            string tag = content.HasTag("security-tamper") ? "security-tamper"
                       : content.HasTag("encoded-payload") ? "encoded"
                       : content.HasTag("reflective-load") ? "reflective"
                       : "amsi-suspicious";
            published += Publish(handler, RuntimeTelemetryEventKind.AmsiScan,
                source, scriptContent, pid, tag);
        }

        return published;
    }

    private int Publish(Action<RuntimeTelemetryEvent> handler,
        RuntimeTelemetryEventKind kind, string source, string content, int pid, string tag)
    {
        try
        {
            handler(new RuntimeTelemetryEvent(
                kind: kind, providerName: Name,
                pid: pid, parentPid: 0,
                processName: source ?? "", imagePath: "",
                commandLine: "", scriptContent: content,
                extraTag: tag,
                timestampUtc: DateTime.UtcNow));
            return 1;
        }
        catch { return 0; }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            Stop();
            EventReceived = null;
        }
    }
}
