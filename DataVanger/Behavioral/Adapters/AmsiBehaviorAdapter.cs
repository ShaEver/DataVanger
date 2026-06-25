using System;

namespace DataVanger.Behavioral.Adapters;

/// <summary>
/// Placeholder for a future AMSI adapter.
///
/// A real implementation will register as an AMSI provider via
/// <c>amsi.dll</c> and republish scan events (PowerShell content,
/// VBScript content, etc.) onto the behavioral bus. For now the
/// adapter is a no-op so the rest of the system can wire to a stable
/// shape without depending on AMSI being available.
/// </summary>
public sealed class AmsiBehaviorAdapter : IDisposable
{
    private readonly IBehavioralEventBus _bus;
    public bool IsAvailable => false;

    public AmsiBehaviorAdapter(IBehavioralEventBus bus)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
    }

    /// <summary>
    /// Forwards an out-of-band AMSI-style content sample (e.g. obtained
    /// via another integration) into the behavioral bus. Returns the
    /// number of events published — currently 0 unless a clear
    /// bypass/encoded-payload signature is detected via
    /// <see cref="DataVanger.Behavioral.Monitors.CommandLineAnalyzer"/>.
    /// </summary>
    public int Submit(string source, string scriptContent, int pid)
    {
        if (string.IsNullOrWhiteSpace(scriptContent)) return 0;
        var findings = DataVanger.Behavioral.Monitors.CommandLineAnalyzer.Analyze(source, scriptContent);
        int published = 0;
        if (findings.HasTag("amsi-bypass"))
        {
            _bus.Publish(new BehavioralEvent(
                kind: BehavioralEventKind.AmsiBypassIndicator,
                pid: pid,
                parentPid: 0,
                processName: source ?? "",
                imagePath: "",
                commandLine: "",
                targetPath: "",
                extraTag: "amsi-bypass",
                severity: BehavioralSeverity.High,
                description: "Conteúdo de script contém indicador de bypass do AMSI",
                timestampUtc: DateTime.UtcNow));
            published++;
        }
        if (findings.HasTag("encoded-payload"))
        {
            _bus.Publish(new BehavioralEvent(
                kind: BehavioralEventKind.EncodedPayload,
                pid: pid,
                parentPid: 0,
                processName: source ?? "",
                imagePath: "",
                commandLine: scriptContent.Length > 256 ? scriptContent[..256] : scriptContent,
                targetPath: "",
                extraTag: "encoded",
                severity: BehavioralSeverity.Medium,
                description: "Conteúdo de script contém payload codificado",
                timestampUtc: DateTime.UtcNow));
            published++;
        }
        return published;
    }

    public void Dispose() { }
}
