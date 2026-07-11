using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using DataVanger.Core;

namespace DataVanger.Reporting.Forensics;

/// <summary>
/// Renders <see cref="ForensicReport"/> instances to JSON, HTML and CSV.
///
/// Exporters are intentionally non-destructive: they NEVER mutate the
/// report, NEVER reclassify findings and NEVER invent severity. All
/// output paths sanitise inputs so HTML reports cannot be used as an
/// XSS vector (anti-FP transparency must not turn into a script
/// injection sink).
/// </summary>
public sealed class ForensicReportExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
    };

    /// <summary>
    /// Defensive cap on the number of timeline rows rendered into the HTML
    /// report. Pathological scans (telemetry floods, multi-hour Deep scans)
    /// can otherwise produce HTML documents big enough to lock up a browser.
    /// When exceeded, a single "truncated" row is appended; the JSON/CSV
    /// surfaces continue to expose the full data.
    /// </summary>
    public const int MaxHtmlTimelineEvents = 25_000;

    public void WriteJson(string path, ForensicReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));
        var payload = ToPayload(report);
        var json = JsonSerializer.Serialize(payload, JsonOptions);
        WriteAllText(path, json);
    }

    public string SerializeJson(ForensicReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));
        return JsonSerializer.Serialize(ToPayload(report), JsonOptions);
    }

    public void WriteCsv(string path, ForensicReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));
        var sb = new StringBuilder();
        sb.AppendLine("IncidentId,Title,Severity,Confidence,ContributingModules,HasMitigations,ChainCount,TimelineEvents,Mitigations");
        foreach (var incident in report.Incidents)
        {
            sb.AppendLine(string.Join(",", new[]
            {
                EscCsv(incident.Id),
                EscCsv(incident.Title),
                EscCsv(incident.Severity.ToString()),
                EscCsv(incident.Confidence.ToString()),
                EscCsv(string.Join("; ", incident.ContributingModules)),
                incident.HasMitigations ? "true" : "false",
                incident.Chains.Count.ToString(),
                incident.Timeline.Count.ToString(),
                EscCsv(string.Join(" | ", incident.MitigationNotes)),
            }));
        }
        WriteAllText(path, sb.ToString());
    }

    public void WriteHtml(string path, ForensicReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));
        WriteAllText(path, RenderHtml(report));
    }

    public string RenderHtml(ForensicReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html lang=\"pt-BR\"><head><meta charset=\"UTF-8\">");
        sb.Append("<title>").Append(HtmlEscape(VersionInfo.DisplayName)).Append(" — Forensic Report</title>");
        sb.Append("<style>body{font-family:Segoe UI,system-ui,sans-serif;background:#0d0d0d;color:#e0e0e0;padding:24px}");
        sb.Append("h1,h2{color:#00ccff}section{border:1px solid #333;border-radius:6px;padding:14px 18px;margin:18px 0;background:#1a1a1a}");
        sb.Append("ul{margin:6px 0 0 18px;padding:0}.mit{color:#8ad}.crit{color:#ff5555}.high{color:#ff8800}");
        sb.Append(".med{color:#ffcc00}.low{color:#88cc88}.inf{color:#888}code{color:#ddd}</style></head><body>");

        sb.Append("<h1>Forensic Report — ").Append(HtmlEscape(report.Metadata.HostName)).Append("</h1>");
        sb.Append("<section><h2>Metadata</h2><ul>");
        sb.Append("<li>Report ID: <code>").Append(HtmlEscape(report.Metadata.ReportId)).Append("</code></li>");
        sb.Append("<li>Scan ID: <code>").Append(HtmlEscape(report.Metadata.ScanId)).Append("</code></li>");
        sb.Append("<li>Engine: ").Append(HtmlEscape(report.Metadata.EngineVersion)).Append("</li>");
        sb.Append("<li>Profile: ").Append(HtmlEscape(report.Metadata.Profile.ToString())).Append("</li>");
        sb.Append("<li>Started (UTC): ").Append(HtmlEscape(report.Metadata.ScanStartedUtc.ToString("O"))).Append("</li>");
        sb.Append("<li>Completed (UTC): ").Append(HtmlEscape(report.Metadata.ScanCompletedUtc.ToString("O"))).Append("</li>");
        sb.Append("<li>Duration: ").Append(HtmlEscape(report.Metadata.Duration.ToString())).Append("</li>");
        sb.Append("</ul></section>");

        sb.Append("<section><h2>Summary</h2><ul>");
        sb.Append("<li>Findings: total=").Append(report.Summary.FindingsTotal)
          .Append(", confirmed=").Append(report.Summary.FindingsConfirmedMalware)
          .Append(", high=").Append(report.Summary.FindingsHighRisk)
          .Append(", suspect=").Append(report.Summary.FindingsSuspect)
          .Append(", clean=").Append(report.Summary.FindingsClean).Append("</li>");
        sb.Append("<li>Incidents: ").Append(report.Summary.IncidentsTotal)
          .Append(" (confirmed=").Append(report.Summary.IncidentsConfirmed)
          .Append(", with mitigations=").Append(report.Summary.IncidentsWithMitigations).Append(")</li>");
        sb.Append("<li>Highest severity: ").Append(HtmlEscape(report.Summary.HighestSeverity.ToString())).Append("</li>");
        sb.Append("<li>Highest confidence: ").Append(HtmlEscape(report.Summary.HighestConfidence.ToString())).Append("</li>");
        sb.Append("<li>Timeline events: ").Append(report.Summary.TimelineEventsTotal).Append("</li>");
        sb.Append("</ul></section>");

        sb.Append("<section><h2>Incidents</h2>");
        if (report.Incidents.Count == 0)
        {
            sb.Append("<p>Nenhum incidente identificado.</p>");
        }
        else
        {
            foreach (var incident in report.Incidents)
            {
                sb.Append("<details open><summary><b class=\"").Append(SeverityCssClass(incident.Severity)).Append("\">")
                  .Append(HtmlEscape(incident.Severity.ToString())).Append("</b> — ")
                  .Append(HtmlEscape(incident.Title)).Append(" (").Append(HtmlEscape(incident.Confidence.ToString())).Append(")</summary>");
                sb.Append("<ul><li>Modules: ").Append(HtmlEscape(string.Join(", ", incident.ContributingModules))).Append("</li>");
                if (incident.MitigationNotes.Count > 0)
                {
                    sb.Append("<li class=\"mit\">Mitigações / contexto anti-FP:<ul>");
                    foreach (var note in incident.MitigationNotes)
                        sb.Append("<li>").Append(HtmlEscape(note)).Append("</li>");
                    sb.Append("</ul></li>");
                }
                sb.Append("<li>Cadeias de evidência:<ul>");
                foreach (var chain in incident.Chains)
                {
                    sb.Append("<li><b>").Append(HtmlEscape(chain.Subject)).Append("</b><ul>");
                    foreach (var node in chain.Nodes)
                    {
                        var css = node.IsMitigation ? "mit" : "";
                        sb.Append("<li class=\"").Append(css).Append("\">")
                          .Append(HtmlEscape(node.ToString())).Append("</li>");
                    }
                    sb.Append("</ul></li>");
                }
                sb.Append("</ul></li></ul></details>");
            }
        }
        sb.Append("</section>");

        sb.Append("<section><h2>Timeline (deterministic)</h2><ul>");
        int timelineRendered = 0;
        int timelineTotal = report.Timeline.Count;
        foreach (var evt in report.Timeline.Ordered())
        {
            if (timelineRendered >= MaxHtmlTimelineEvents)
            {
                int omitted = timelineTotal - timelineRendered;
                if (omitted > 0)
                {
                    sb.Append("<li class=\"inf\"><em>[+ ").Append(omitted)
                      .Append(" eventos omitidos para preservar a responsividade do navegador; consulte o JSON/CSV para o histórico completo]</em></li>");
                }
                break;
            }
            sb.Append("<li class=\"").Append(SeverityCssClass(evt.Severity)).Append("\">")
              .Append(HtmlEscape(evt.ToString())).Append("</li>");
            timelineRendered++;
        }
        sb.Append("</ul></section>");

        sb.Append("</body></html>");
        return sb.ToString();
    }

    private static object ToPayload(ForensicReport report) => new
    {
        metadata = new
        {
            reportId = report.Metadata.ReportId,
            scanId = report.Metadata.ScanId,
            engineVersion = report.Metadata.EngineVersion,
            profile = report.Metadata.Profile.ToString(),
            scanStartedUtc = report.Metadata.ScanStartedUtc,
            scanCompletedUtc = report.Metadata.ScanCompletedUtc,
            durationSeconds = report.Metadata.Duration.TotalSeconds,
            hostName = report.Metadata.HostName,
        },
        summary = new
        {
            findingsTotal = report.Summary.FindingsTotal,
            findingsConfirmedMalware = report.Summary.FindingsConfirmedMalware,
            findingsHighRisk = report.Summary.FindingsHighRisk,
            findingsSuspect = report.Summary.FindingsSuspect,
            findingsClean = report.Summary.FindingsClean,
            incidentsTotal = report.Summary.IncidentsTotal,
            incidentsConfirmed = report.Summary.IncidentsConfirmed,
            incidentsWithMitigations = report.Summary.IncidentsWithMitigations,
            timelineEventsTotal = report.Summary.TimelineEventsTotal,
            behavioralEventsConsumed = report.Summary.BehavioralEventsConsumed,
            memoryFindingsConsumed = report.Summary.MemoryFindingsConsumed,
            runtimeEventsConsumed = report.Summary.RuntimeEventsConsumed,
            schedulerExecutionsConsumed = report.Summary.SchedulerExecutionsConsumed,
            highestSeverity = report.Summary.HighestSeverity.ToString(),
            highestConfidence = report.Summary.HighestConfidence.ToString(),
        },
        incidents = report.Incidents.Select(i => new
        {
            id = i.Id,
            title = i.Title,
            severity = i.Severity.ToString(),
            confidence = i.Confidence.ToString(),
            contributingModules = i.ContributingModules,
            hasMitigations = i.HasMitigations,
            mitigationNotes = i.MitigationNotes,
            chains = i.Chains.Select(SerializeChain),
            timeline = i.Timeline.Select(SerializeTimelineEvent),
            isConfirmed = i.IsConfirmed,
        }),
        evidenceChains = report.EvidenceChains.Select(SerializeChain),
        timeline = report.Timeline.Ordered().Select(SerializeTimelineEvent),
    };

    private static object SerializeChain(EvidenceChain chain) => new
    {
        targetId = chain.TargetId,
        subject = chain.Subject,
        totalScoreDelta = chain.TotalScoreDelta,
        hasConfirmedEvidence = chain.HasConfirmedEvidence,
        contributingModules = chain.ContributingModules,
        nodes = chain.Nodes.Select(n => new
        {
            sourceModule = n.SourceModule,
            category = n.Category,
            description = n.Description,
            scoreDelta = n.ScoreDelta,
            strength = n.Strength.ToString(),
            canConfirmMalware = n.CanConfirmMalware,
            timestampUtc = n.TimestampUtc,
            correlationId = n.CorrelationId,
            mitigationNote = n.MitigationNote,
            isMitigation = n.IsMitigation,
        }),
    };

    private static object SerializeTimelineEvent(TimelineEvent e) => new
    {
        timestampUtc = e.TimestampUtc,
        sourceModule = e.SourceModule,
        category = e.Category,
        description = e.Description,
        processId = e.ProcessId,
        processName = e.ProcessName,
        severity = e.Severity.ToString(),
        correlationId = e.CorrelationId,
    };

    // Phase 07 — CSV export hardening: delegate to the shared CsvSafe so forensic
    // CSV also neutralizes spreadsheet formula injection (not just RFC 4180 quoting).
    private static string EscCsv(string? value) => CsvSafe.Field(value);

    private static string HtmlEscape(string? value) =>
        (value ?? "")
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;")
            .Replace("'", "&#39;");

    private static string SeverityCssClass(ForensicSeverity severity) => severity switch
    {
        ForensicSeverity.ConfirmedMalware => "crit",
        ForensicSeverity.Critical => "crit",
        ForensicSeverity.High => "high",
        ForensicSeverity.Medium => "med",
        ForensicSeverity.Low => "low",
        _ => "inf",
    };

    private static void WriteAllText(string path, string content)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }
        File.WriteAllText(path, content, Encoding.UTF8);
    }
}
