using System;

namespace DataVanger.Runtime.Amsi;

/// <summary>
/// Safe AMSI provider used when no real AMSI integration is available.
///
/// It still accepts <see cref="SubmitContent"/> calls so callers can
/// feed out-of-band script samples (e.g. from a script monitor, from a
/// future PowerShell ETW translator), but it never claims to be "live"
/// AMSI — <see cref="IsHostSupported"/> stays false. Bypass detection
/// still runs on submitted content.
/// </summary>
public sealed class NullAmsiProvider : IAmsiTelemetryProvider
{
    public string Name => "null-amsi";
    public RuntimeProviderState State { get; private set; } = RuntimeProviderState.NotStarted;
    /// <summary>The null provider is never "running" — see <see cref="State"/> for diagnostics.</summary>
    public bool IsRunning => false;
    public bool IsHostSupported => false;

    public event Action<RuntimeTelemetryEvent>? EventReceived;

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

    public int SubmitContent(string source, string scriptContent, int pid)
    {
        // Even on the null provider we still surface clear AMSI-bypass
        // signatures — it's the only AMSI-like signal we can offer when
        // the real provider isn't around.
        if (string.IsNullOrWhiteSpace(scriptContent)) return 0;
        var handler = EventReceived;
        if (handler is null) return 0;

        int published = 0;
        var reasons = AmsiBypassDetector.Detect(scriptContent);
        if (reasons.Count > 0)
        {
            try
            {
                handler(new RuntimeTelemetryEvent(
                    kind: RuntimeTelemetryEventKind.AmsiBypassIndicator,
                    providerName: Name,
                    pid: pid, parentPid: 0,
                    processName: source ?? "", imagePath: "",
                    commandLine: "", scriptContent: scriptContent,
                    extraTag: "amsi-bypass",
                    timestampUtc: DateTime.UtcNow));
                published++;
            }
            catch (Exception) { /* Event sink callback must never throw back into the provider - swallow intentionally. */ }
        }
        return published;
    }

    public void Dispose() => Stop();
}
