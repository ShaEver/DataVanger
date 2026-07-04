using System;
using System.Collections.Generic;

namespace DataVanger.Runtime.Amsi;

/// <summary>
/// Shared, side-effect-free builder that turns a script/content sample into the
/// zero, one, or two <see cref="RuntimeTelemetryEvent"/>s an AMSI provider
/// should publish for it. Extracted so the in-memory provider and the real
/// ingest provider emit byte-for-byte identical telemetry (same kinds, same
/// tags, same ordering) — the anti-duplication and coexistence guarantees in
/// the design depend on both paths producing the same normalized events.
///
/// It only tags/classifies content; it NEVER makes a malware verdict and NEVER
/// blocks. Benign content yields an empty list.
/// </summary>
internal static class AmsiContentEvents
{
    /// <summary>
    /// Builds the telemetry events for <paramref name="scriptContent"/>. Order
    /// is stable and intentional: an AMSI-bypass indicator (if any) is emitted
    /// before a suspicious-content scan event, matching the historical
    /// in-memory provider behaviour that downstream tests pin.
    /// </summary>
    public static IReadOnlyList<RuntimeTelemetryEvent> Build(
        string providerName, string source, string scriptContent, int pid)
    {
        if (string.IsNullOrWhiteSpace(scriptContent))
            return Array.Empty<RuntimeTelemetryEvent>();

        var events = new List<RuntimeTelemetryEvent>(2);

        var bypassReasons = AmsiBypassDetector.Detect(scriptContent);
        if (bypassReasons.Count > 0)
        {
            events.Add(New(providerName, RuntimeTelemetryEventKind.AmsiBypassIndicator,
                source, scriptContent, pid, "amsi-bypass"));
        }

        var content = AmsiContentAnalyzer.Analyze(source, scriptContent);
        // Surface a generic AmsiScan event when there is at least one suspicious
        // content tag. Benign scripts produce zero scan events.
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
            events.Add(New(providerName, RuntimeTelemetryEventKind.AmsiScan,
                source, scriptContent, pid, tag));
        }

        return events;
    }

    private static RuntimeTelemetryEvent New(
        string providerName, RuntimeTelemetryEventKind kind,
        string source, string content, int pid, string tag)
        => new(
            kind: kind, providerName: providerName,
            pid: pid, parentPid: 0,
            processName: source ?? "", imagePath: "",
            commandLine: "", scriptContent: content,
            extraTag: tag,
            timestampUtc: DateTime.UtcNow);
}
