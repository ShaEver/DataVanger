namespace DataVanger.Runtime.Amsi;

/// <summary>
/// Marker interface for AMSI-backed telemetry providers.
///
/// AMSI integration in DataVanger is intentionally read-only: the
/// provider observes script content surfaced via AMSI (or supplied
/// out-of-band) and emits normalized telemetry. It never patches
/// amsi.dll, never weakens AMSI for other consumers and never blocks
/// script execution — those would all be active-defense behaviors,
/// out of scope for this layer.
/// </summary>
public interface IAmsiTelemetryProvider : IRuntimeTelemetryProvider
{
    /// <summary>True when the host environment exposes AMSI to this process.</summary>
    bool IsHostSupported { get; }

    /// <summary>
    /// Submit a script/content sample for analysis. Returns the number of
    /// telemetry events that were published (0 when nothing suspicious
    /// was found). Safe to call from any thread.
    /// </summary>
    int SubmitContent(string source, string scriptContent, int pid);
}
