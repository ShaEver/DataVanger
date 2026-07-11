using System;

namespace DataVanger.Runtime;

/// <summary>
/// Normalized telemetry event surfaced by an ETW or AMSI provider.
///
/// Providers must NEVER raise events that can confirm malware on their
/// own — the entire runtime telemetry pipeline is heuristic. The bridge
/// translates these into <see cref="DataVanger.Behavioral.BehavioralEvent"/>
/// instances and lets the rule/correlation engines decide what (if
/// anything) deserves to influence scoring.
///
/// Strings are stored verbatim but the constructor truncates oversized
/// script content so a noisy provider can't blow up memory. The hard cap
/// is 16 KB per event — large enough for realistic scripts, small enough
/// to keep the bus bounded.
/// </summary>
public sealed class RuntimeTelemetryEvent
{
    public const int MaxScriptContentLength = 16 * 1024;
    public const int MaxCommandLineLength   = 4 * 1024;

    public RuntimeTelemetryEvent(
        RuntimeTelemetryEventKind kind,
        string providerName,
        int pid,
        int parentPid,
        string processName,
        string imagePath,
        string commandLine,
        string? scriptContent,
        string? extraTag,
        DateTime timestampUtc)
    {
        Kind          = kind;
        ProviderName  = providerName ?? "";
        Pid           = pid;
        ParentPid     = parentPid;
        ProcessName   = processName ?? "";
        ImagePath     = imagePath ?? "";
        CommandLine   = Truncate(commandLine ?? "", MaxCommandLineLength);
        ScriptContent = Truncate(scriptContent ?? "", MaxScriptContentLength);
        ExtraTag      = extraTag ?? "";
        TimestampUtc  = timestampUtc == default ? DateTime.UtcNow : timestampUtc.ToUniversalTime();
    }

    public RuntimeTelemetryEventKind Kind { get; }
    public string ProviderName { get; }
    public int    Pid          { get; }
    public int    ParentPid    { get; }
    public string ProcessName  { get; }
    public string ImagePath    { get; }
    public string CommandLine  { get; }
    public string ScriptContent { get; }
    public string ExtraTag     { get; }
    public DateTime TimestampUtc { get; }

    public override string ToString()
        => $"[{TimestampUtc:HH:mm:ss.fff}] {Kind} via={ProviderName} pid={Pid} {ProcessName} tag={ExtraTag}";

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value.Substring(0, maxLength);
}
