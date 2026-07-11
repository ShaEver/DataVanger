using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Classification;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;
using DataVanger.Detection;
using DataVanger.Engine;
using DataVanger.Memory;
using DataVanger.Memory.Readers;
using DataVanger.Memory.Rules;
using DataVanger.Reputation;
using static DataVanger.Tests.Fixtures.PeFactory;

// Phase 09 decomposition — Reporting & Forensics (explainability/timeline/incident aggregation). Filter: ~Reporting.
// Faithful move of the legacy mega-[Fact] section into an independently
// runnable, filterable [Fact]. Body is verbatim; the private Assert shim
// delegates to LegacyAssert.True so condition AND message are preserved.
public class ReportingForensicsTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public void ReportingAndForensics_AllLegacyChecks()
// 22. Reporting & Forensics — explainability, timeline, incident aggregation
// ============================================================================
{
    static ScanFinding HeuristicFinding(string path, int score, params (string Cat, string Desc, int Delta, EvidenceStrength Str)[] evidence)
    {
        var f = new ScanFinding { Path = path, Score = score };
        foreach (var e in evidence)
        {
            f.Evidence.Add(new Evidence
            {
                Category = e.Cat,
                Description = e.Desc,
                ScoreDelta = e.Delta,
                Strength = e.Str,
                CanConfirmMalware = false,
            });
        }
        return f;
    }

    // 22a. Heuristic-only finding never reaches ConfirmedMalware severity in the report.
    var heuristic = HeuristicFinding(
        @"C:\Users\Test\AppData\Roaming\notsvchost.exe",
        RiskThresholds.Critical + 8,
        ("Heuristic", "Nome de processo de sistema fora de System32", 8, EvidenceStrength.High),
        ("Persistence", "Persistência em Run key", 4, EvidenceStrength.Medium),
        ("Script", "PowerShell EncodedCommand suspeito", 5, EvidenceStrength.High));
    Assert(!heuristic.IsConfirmedMalware,
        "Heuristic-only finding must not be classified as confirmed by the underlying policy.");

    var heuristicInput = new DataVanger.Reporting.Forensics.ForensicReportInput
    {
        Findings = new[] { heuristic },
        ScanStartedUtc = new DateTime(2026, 1, 1, 9, 0, 0, DateTimeKind.Utc),
        ScanCompletedUtc = new DateTime(2026, 1, 1, 9, 0, 30, DateTimeKind.Utc),
        ScanId = "scan-heur",
        HostName = "TEST-HOST",
    };
    var heuristicReport = new DataVanger.Reporting.Forensics.ForensicReportBuilder().Build(heuristicInput);
    Assert(heuristicReport.Incidents.Count == 1,
        "A heuristic finding must produce exactly one incident.");
    Assert(heuristicReport.Incidents[0].Severity != DataVanger.Reporting.Forensics.ForensicSeverity.ConfirmedMalware,
        "Heuristic-only evidence chains must never become ConfirmedMalware incidents.");
    Assert(heuristicReport.Incidents[0].Severity == DataVanger.Reporting.Forensics.ForensicSeverity.Critical
        || heuristicReport.Incidents[0].Severity == DataVanger.Reporting.Forensics.ForensicSeverity.High,
        "Heuristic critical-score finding must map to Critical/High forensic severity.");
    Assert(!heuristicReport.Incidents[0].IsConfirmed,
        "Heuristic incident must not be flagged as confirmed.");
    Assert(heuristicReport.EvidenceChains[0].Nodes.All(n => !n.CanConfirmMalware),
        "Evidence chain nodes built from heuristic evidence must not flip CanConfirmMalware.");

    // 22b. Blacklist hash propagates ConfirmedMalware severity into the forensic report.
    var confirmed = new ScanFinding
    {
        Path = @"C:\Users\Test\Downloads\payload.exe",
        Score = RiskThresholds.Critical,
        IsBlacklisted = true,
    };
    confirmed.Evidence.Add(new Evidence
    {
        Category = "Signature",
        Description = "Hash em lista de malware conhecido",
        ScoreDelta = 12,
        Strength = EvidenceStrength.Confirmed,
        CanConfirmMalware = true,
    });
    Assert(confirmed.IsConfirmedMalware, "Blacklist + confirmed evidence must be classified as confirmed malware.");

    var confirmedReport = new DataVanger.Reporting.Forensics.ForensicReportBuilder().Build(
        new DataVanger.Reporting.Forensics.ForensicReportInput
        {
            Findings = new[] { confirmed },
            ScanStartedUtc = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc),
            ScanCompletedUtc = new DateTime(2026, 1, 1, 10, 0, 5, DateTimeKind.Utc),
        });
    Assert(confirmedReport.Incidents.Count == 1
        && confirmedReport.Incidents[0].Severity == DataVanger.Reporting.Forensics.ForensicSeverity.ConfirmedMalware
        && confirmedReport.Incidents[0].IsConfirmed,
        "Confirmed-malware finding must surface as a ConfirmedMalware incident.");
    Assert(confirmedReport.Incidents[0].Chains[0].HasConfirmedEvidence,
        "Confirmed-malware incident must expose at least one chain with confirmed evidence.");
    Assert(confirmedReport.Summary.HighestSeverity == DataVanger.Reporting.Forensics.ForensicSeverity.ConfirmedMalware,
        "Forensic summary must surface ConfirmedMalware as the highest severity.");

    // 22c. False-positive transparency: reputation-driven mitigations are preserved.
    var mitigated = new ScanFinding
    {
        Path = @"C:\Users\Test\AppData\Local\Vendor\trusted.exe",
        Score = RiskThresholds.High,
        ReputationState = DataVanger.Reputation.ReputationTrustState.LikelyGood,
        ReputationScoreDelta = -3,
        ReputationReasons = new List<string> { "Publisher conhecido", "Hash visto em muitos hosts" },
    };
    mitigated.Evidence.Add(new Evidence
    {
        Category = "Heuristic",
        Description = "Local incomum de execução",
        ScoreDelta = 3,
        Strength = EvidenceStrength.Medium,
    });
    var mitigatedReport = new DataVanger.Reporting.Forensics.ForensicReportBuilder().Build(
        new DataVanger.Reporting.Forensics.ForensicReportInput { Findings = new[] { mitigated } });
    var mitigatedIncident = mitigatedReport.Incidents.Single();
    Assert(mitigatedIncident.HasMitigations,
        "Reputation-reduced severity must surface as a mitigation in the forensic report.");
    Assert(mitigatedIncident.MitigationNotes.Any(n => n.Contains("reputation", StringComparison.OrdinalIgnoreCase)),
        "Mitigation notes must reference the reputation context explicitly.");
    Assert(mitigatedIncident.Severity != DataVanger.Reporting.Forensics.ForensicSeverity.ConfirmedMalware,
        "Mitigated heuristic incident must never be classified as ConfirmedMalware.");

    // 22d. Browser-extension finding adds the dedicated FP-mitigation node.
    var extension = new ScanFinding
    {
        Path = @"C:\Users\Test\AppData\Local\Google\Chrome\User Data\Default\Extensions\abcdefg\manifest.json",
        Score = RiskThresholds.Suspect,
        Reasons = "Permissão sensível em manifesto Chromium",
        ReputationState = DataVanger.Reputation.ReputationTrustState.LikelyGood,
    };
    var extensionReport = new DataVanger.Reporting.Forensics.ForensicReportBuilder().Build(
        new DataVanger.Reporting.Forensics.ForensicReportInput { Findings = new[] { extension } });
    var extensionChain = extensionReport.EvidenceChains.Single();
    Assert(extensionChain.Mitigations.Any(m => m.SourceModule == "BrowserExtensionIntelligence"),
        "Browser extension findings must include the FP-mitigation context node.");
    Assert(extensionReport.Incidents.Single().Severity < DataVanger.Reporting.Forensics.ForensicSeverity.ConfirmedMalware,
        "Browser-extension heuristic must never become ConfirmedMalware.");

    // 22e. Timeline is fully deterministic — repeated builds produce identical ordering.
    var ts = new DateTime(2026, 1, 2, 12, 0, 0, DateTimeKind.Utc);
    var beh = new[]
    {
        new DataVanger.Behavioral.BehavioralEvent(
            DataVanger.Behavioral.BehavioralEventKind.ProcessStart,
            1000, 800, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell -enc ...", "", "encodedcommand",
            DataVanger.Behavioral.BehavioralSeverity.High, "PS encoded", ts.AddSeconds(2)),
        new DataVanger.Behavioral.BehavioralEvent(
            DataVanger.Behavioral.BehavioralEventKind.ProcessStart,
            800, 4, "winword.exe", @"C:\Program Files\Microsoft Office\winword.exe",
            "winword", "", "office",
            DataVanger.Behavioral.BehavioralSeverity.Medium, "Office launched", ts.AddSeconds(1)),
    };
    var mem = new[]
    {
        new DataVanger.Memory.MemoryFinding(
            DataVanger.Memory.MemoryFindingKind.HighEntropyExecutable, 1000, "powershell.exe",
            0x10000UL, 4096,
            DataVanger.Memory.MemoryProtection.Read | DataVanger.Memory.MemoryProtection.Write | DataVanger.Memory.MemoryProtection.Execute,
            DataVanger.Memory.MemoryRegionKind.Private,
            DataVanger.Memory.MemoryScanSeverity.High, "High entropy in RWX", 5, ts.AddSeconds(3),
            backingPath: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    };
    var runtime = new[]
    {
        new DataVanger.Runtime.RuntimeTelemetryEvent(
            DataVanger.Runtime.RuntimeTelemetryEventKind.AmsiScan,
            "AMSI", 1000, 800, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell -enc ...", "ScriptBlock", "amsi-bypass-attempt", ts.AddSeconds(4)),
    };
    var sched = new[]
    {
        new DataVanger.Scheduling.Models.ScheduledJobExecution
        {
            JobId = "nightly",
            JobName = "Nightly scan",
            StartedUtc = ts.AddSeconds(0),
            CompletedUtc = ts.AddSeconds(10),
            Outcome = DataVanger.Scheduling.Models.JobRunOutcome.Failed,
            Message = "synthetic failure",
        },
    };
    var input = new DataVanger.Reporting.Forensics.ForensicReportInput
    {
        Findings = new[] { heuristic },
        BehavioralEvents = beh,
        MemoryFindings = mem,
        RuntimeEvents = runtime,
        SchedulerExecutions = sched,
        ScanStartedUtc = ts,
        ScanCompletedUtc = ts.AddSeconds(15),
    };

    var firstReport = new DataVanger.Reporting.Forensics.ForensicReportBuilder().Build(input);
    var secondReport = new DataVanger.Reporting.Forensics.ForensicReportBuilder().Build(input);

    var firstOrder = firstReport.Timeline.Ordered().Select(e => e.Description).ToList();
    var secondOrder = secondReport.Timeline.Ordered().Select(e => e.Description).ToList();
    Assert(firstOrder.SequenceEqual(secondOrder),
        "Forensic timeline ordering must be deterministic across repeated builds.");

    var timestamps = firstReport.Timeline.Ordered().Select(e => e.TimestampUtc).ToList();
    for (int i = 1; i < timestamps.Count; i++)
    {
        Assert(timestamps[i] >= timestamps[i - 1],
            "Timeline must be sorted ascending by UTC timestamp.");
    }
    Assert(firstReport.Summary.BehavioralEventsConsumed == 2
        && firstReport.Summary.MemoryFindingsConsumed == 1
        && firstReport.Summary.RuntimeEventsConsumed == 1
        && firstReport.Summary.SchedulerExecutionsConsumed == 1,
        "Forensic summary must count consumed events from every integrated module.");

    // 22f. Scheduler failures never produce malware incidents.
    Assert(firstReport.Incidents.All(i => i.Severity != DataVanger.Reporting.Forensics.ForensicSeverity.ConfirmedMalware
                                          || i.Chains.Any(c => c.HasConfirmedEvidence)),
        "Scheduler failures must never inflate an incident to ConfirmedMalware.");
    Assert(firstReport.Timeline.Ordered().Any(e => e.SourceModule == "Scheduler"
                                                   && e.Severity <= DataVanger.Reporting.Forensics.ForensicSeverity.Medium),
        "Scheduler events must be reported with severity capped at Medium.");

    // 22g. Incident aggregation merges chains that share a correlation id.
    var aggInput = new DataVanger.Reporting.Forensics.ForensicReportInput
    {
        Findings = new[]
        {
            HeuristicFinding(@"C:\sample\a.exe", RiskThresholds.High,
                ("Script", "PS encoded", 5, EvidenceStrength.High)),
            HeuristicFinding(@"C:\sample\b.exe", RiskThresholds.Suspect + 1,
                ("Persistence", "Run key write", 4, EvidenceStrength.Medium)),
        },
    };
    var aggReport = new DataVanger.Reporting.Forensics.ForensicReportBuilder().Build(aggInput);
    // Different targets and no correlation id ⇒ two incidents.
    Assert(aggReport.Incidents.Count == 2,
        "Distinct targets without correlation id must produce distinct incidents.");

    // 22h. JSON export round-trips and remains XSS-safe in HTML.
    var exporter = new DataVanger.Reporting.Forensics.ForensicReportExporter();
    string json = exporter.SerializeJson(firstReport);
    Assert(json.Contains("\"incidents\":") && json.Contains("\"timeline\":") && json.Contains("\"evidenceChains\":"),
        "Forensic JSON export must include incidents, timeline and evidence chains.");
    string html = exporter.RenderHtml(firstReport);
    Assert(html.StartsWith("<!DOCTYPE html>") && html.Contains("Forensic Report"),
        "Forensic HTML export must produce a well-formed document.");

    var xssFinding = HeuristicFinding(@"C:\<script>alert(1)</script>\evil.exe", RiskThresholds.Suspect,
        ("Heuristic", "<img src=x onerror=alert(1)>", 3, EvidenceStrength.Medium));
    var xssReport = new DataVanger.Reporting.Forensics.ForensicReportBuilder().Build(
        new DataVanger.Reporting.Forensics.ForensicReportInput { Findings = new[] { xssFinding } });
    string xssHtml = exporter.RenderHtml(xssReport);
    Assert(!xssHtml.Contains("<script>alert"),
        "HTML exporter must escape script tags from path values.");
    Assert(!xssHtml.Contains("<img src=x onerror=alert(1)>"),
        "HTML exporter must escape script tags from evidence descriptions.");

    // 22i. IReportService surface integrates forensic builder/exporter.
    var reportService = new DataVanger.Reporting.ReportService();
    var built = reportService.BuildForensicReport(heuristicInput);
    Assert(built.Incidents.Count == 1 && !built.Incidents[0].IsConfirmed,
        "IReportService.BuildForensicReport must preserve anti-FP invariants.");

    string tempDir = Path.Combine(Path.GetTempPath(), "dv-forensics-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(tempDir);
    try
    {
        string jsonPath = Path.Combine(tempDir, "report.json");
        string htmlPath = Path.Combine(tempDir, "report.html");
        string csvPath = Path.Combine(tempDir, "report.csv");
        reportService.WriteForensicJson(jsonPath, built);
        reportService.WriteForensicHtml(htmlPath, built);
        reportService.WriteForensicCsv(csvPath, built);
        Assert(File.Exists(jsonPath) && new FileInfo(jsonPath).Length > 0,
            "WriteForensicJson must produce a non-empty file.");
        Assert(File.Exists(htmlPath) && new FileInfo(htmlPath).Length > 0,
            "WriteForensicHtml must produce a non-empty file.");
        Assert(File.Exists(csvPath) && new FileInfo(csvPath).Length > 0,
            "WriteForensicCsv must produce a non-empty file.");
        string csvContent = File.ReadAllText(csvPath);
        Assert(csvContent.StartsWith("IncidentId,Title,"),
            "Forensic CSV export must include the incident header row.");
    }
    finally
    {
        try { Directory.Delete(tempDir, true); } catch (Exception) { /* temp cleanup - ignore if already removed */ }
    }

    // 22j. Memory/runtime/behavioral evidence alone must not become ConfirmedMalware.
    var nonFindingInput = new DataVanger.Reporting.Forensics.ForensicReportInput
    {
        BehavioralEvents = beh,
        MemoryFindings = mem,
        RuntimeEvents = runtime,
        SchedulerExecutions = sched,
        ScanStartedUtc = ts,
        ScanCompletedUtc = ts.AddSeconds(15),
    };
    var nonFindingReport = new DataVanger.Reporting.Forensics.ForensicReportBuilder().Build(nonFindingInput);
    Assert(nonFindingReport.Incidents.Count == 0,
        "Telemetry alone (no findings) must produce zero incidents.");
    Assert(nonFindingReport.Timeline.Count >= 4,
        "Telemetry events must still populate the forensic timeline.");

    // 22k. Empty input is tolerated and produces an empty but valid report.
    var emptyReport = new DataVanger.Reporting.Forensics.ForensicReportBuilder().Build(new DataVanger.Reporting.Forensics.ForensicReportInput());
    Assert(emptyReport.Incidents.Count == 0 && emptyReport.Timeline.Count == 0,
        "Empty input must yield an empty report with no exceptions.");
    Assert(emptyReport.Summary.HighestSeverity == DataVanger.Reporting.Forensics.ForensicSeverity.Informational,
        "Empty report must report Informational as the highest severity.");
}

// ============================================================================
}
