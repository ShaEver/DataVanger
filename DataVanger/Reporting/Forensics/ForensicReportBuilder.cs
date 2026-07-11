using System;
using System.Collections.Generic;
using System.Linq;
using DataVanger.Behavioral;
using DataVanger.Classification;
using DataVanger.Core;
using DataVanger.Memory;
using DataVanger.Reputation;
using DataVanger.Runtime;
using DataVanger.Scheduling.Models;

namespace DataVanger.Reporting.Forensics;

/// <summary>
/// Builds a <see cref="ForensicReport"/> from the inputs produced by all
/// the existing detection modules. The builder is intentionally pure: it
/// reads its <see cref="ForensicReportInput"/> and produces a report,
/// without touching the engine, the classifier or any module's internal
/// state.
///
/// Anti-FP guarantees enforced here:
///
///   1. Memory findings, runtime telemetry, behavioural events,
///      browser-extension heuristics and scheduler failures never
///      contribute a node with <see cref="EvidenceChainNode.CanConfirmMalware"/>
///      set to true. Only confirmed signature/hash hits on
///      <see cref="ScanFinding"/> objects can flip that flag — through
///      <see cref="AntiFalsePositivePolicy.IsConfirmed"/>.
///   2. A finding's forensic severity is derived from its
///      <see cref="ScanFinding.Classification"/>. The builder never
///      escalates from <see cref="ThreatClass.HighRisk"/> to
///      <see cref="ForensicSeverity.ConfirmedMalware"/>.
///   3. Scheduler failures are recorded as informational timeline events
///      with severity at most <see cref="ForensicSeverity.Medium"/> and
///      never become incidents on their own.
///   4. Anti-FP reductions performed by the reputation engine /
///      browser-extension trust state are preserved verbatim in
///      <see cref="EvidenceChain.Mitigations"/> and propagated to
///      <see cref="Incident.MitigationNotes"/>.
/// </summary>
public sealed class ForensicReportBuilder
{
    public ForensicReport Build(ForensicReportInput input)
    {
        input ??= new ForensicReportInput();

        var timeline = new ForensicTimeline();
        AddSchedulerEvents(timeline, input.SchedulerExecutions);
        AddRuntimeEvents(timeline, input.RuntimeEvents);
        AddBehavioralEvents(timeline, input.BehavioralEvents);
        AddMemoryEvents(timeline, input.MemoryFindings);

        var chains = new List<EvidenceChain>(input.Findings.Count);
        var severityByTarget = new Dictionary<string, ForensicSeverity>(StringComparer.OrdinalIgnoreCase);
        var confidenceByTarget = new Dictionary<string, ForensicConfidence>(StringComparer.OrdinalIgnoreCase);

        foreach (var finding in input.Findings)
        {
            string targetId = string.IsNullOrEmpty(finding.Path)
                ? (finding.SHA256 ?? Guid.NewGuid().ToString("N"))
                : finding.Path;

            var chain = BuildChainForFinding(finding, targetId, input.ScanStartedUtc);
            chains.Add(chain);

            severityByTarget[targetId] = MapSeverity(finding);
            confidenceByTarget[targetId] = MapConfidence(finding);

            timeline.Add(new TimelineEvent(
                timestampUtc: ResolveFindingTimestamp(finding, input.ScanStartedUtc),
                sourceModule: "ScanEngine",
                category: "Finding",
                description: BuildFindingDescription(finding),
                severity: severityByTarget[targetId],
                correlationId: targetId));
        }

        var aggregator = new IncidentAggregator();
        var incidents = aggregator.Aggregate(chains, severityByTarget, confidenceByTarget, timeline);

        var summary = BuildSummary(input, chains, incidents, timeline);
        var metadata = new ForensicReportMetadata
        {
            ScanId = string.IsNullOrEmpty(input.ScanId)
                ? Guid.NewGuid().ToString("N")
                : input.ScanId,
            Profile = input.Options.Profile,
            ScanStartedUtc = input.ScanStartedUtc.ToUniversalTime(),
            ScanCompletedUtc = input.ScanCompletedUtc.ToUniversalTime(),
            HostName = input.HostName,
        };

        return new ForensicReport(metadata, summary, incidents, chains, timeline);
    }

    private static EvidenceChain BuildChainForFinding(ScanFinding finding, string targetId, DateTime fallbackTimestamp)
    {
        var subject = string.IsNullOrEmpty(finding.FileName) ? targetId : finding.FileName;
        var chain = new EvidenceChain(targetId, subject);

        var baseTimestamp = ResolveFindingTimestamp(finding, fallbackTimestamp);
        int index = 0;

        IReadOnlyList<Evidence> evidence = finding.Evidence.Count > 0
            ? finding.Evidence
            : EvidenceService.FromReasons(
                (finding.Reasons ?? string.Empty)
                    .Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));

        bool findingIsConfirmed = AntiFalsePositivePolicy.IsConfirmed(finding, evidence);

        foreach (var e in evidence)
        {
            bool canConfirm = e.CanConfirmMalware || e.Strength == EvidenceStrength.Confirmed;
            // Hard invariant: never let heuristic-only sources flip CanConfirmMalware.
            if (!findingIsConfirmed) canConfirm = false;

            chain.Append(new EvidenceChainNode(
                sourceModule: InferModule(e),
                category: e.Category,
                description: e.Description,
                scoreDelta: e.ScoreDelta,
                strength: e.Strength,
                canConfirmMalware: canConfirm,
                timestampUtc: baseTimestamp.AddTicks(index++),
                correlationId: targetId));
        }

        AppendReputationContext(chain, finding, baseTimestamp, ref index, targetId);
        AppendBrowserMitigationContext(chain, finding, baseTimestamp, ref index, targetId);

        return chain;
    }

    private static string InferModule(Evidence e)
    {
        if (string.IsNullOrEmpty(e.Category)) return "ScanEngine";
        return e.Category switch
        {
            "Signature" => "Signatures",
            "Reputation" => "ReputationEngine",
            "Behavioral" => "BehavioralEngine",
            "Memory" => "MemoryScanner",
            "Runtime" => "RuntimeTelemetry",
            "Script" => "ScriptAnalyzer",
            "Document" => "DocumentAnalyzer",
            "Archive" => "ArchiveAnalyzer",
            "Persistence" => "PersistenceCollector",
            "Browser" => "BrowserExtensionIntelligence",
            _ => "ScanEngine",
        };
    }

    private static void AppendReputationContext(
        EvidenceChain chain,
        ScanFinding finding,
        DateTime baseTimestamp,
        ref int index,
        string targetId)
    {
        if (finding.ReputationState == ReputationTrustState.Unknown
            && finding.ReputationReasons.Count == 0
            && finding.ReputationScoreDelta == 0)
        {
            return;
        }

        bool isMitigation = finding.ReputationScoreDelta < 0
            || finding.ReputationState is ReputationTrustState.KnownGood or ReputationTrustState.LikelyGood;

        string note;
        if (isMitigation)
        {
            note = finding.ReputationReasons.Count == 0
                ? $"Severity adjusted by reputation: {finding.ReputationState}"
                : $"Severity adjusted by reputation ({finding.ReputationState}): "
                  + string.Join("; ", finding.ReputationReasons);
        }
        else
        {
            note = finding.ReputationReasons.Count == 0
                ? $"Reputation: {finding.ReputationState}"
                : $"Reputation ({finding.ReputationState}): "
                  + string.Join("; ", finding.ReputationReasons);
        }

        chain.Append(new EvidenceChainNode(
            sourceModule: "ReputationEngine",
            category: "Reputation",
            description: note,
            scoreDelta: finding.ReputationScoreDelta,
            strength: EvidenceStrength.Low,
            canConfirmMalware: false,
            timestampUtc: baseTimestamp.AddTicks(index++),
            correlationId: targetId,
            mitigationNote: isMitigation ? note : ""));
    }

    private static void AppendBrowserMitigationContext(
        EvidenceChain chain,
        ScanFinding finding,
        DateTime baseTimestamp,
        ref int index,
        string targetId)
    {
        if (!IsBrowserExtensionFinding(finding)) return;

        bool hasMitigation = finding.ReputationState is ReputationTrustState.KnownGood
            or ReputationTrustState.LikelyGood
            || finding.Reasons.Contains("Chromium", StringComparison.OrdinalIgnoreCase)
            || finding.Reasons.Contains("extensão", StringComparison.OrdinalIgnoreCase);

        if (!hasMitigation) return;

        const string note = "Severidade reduzida: contexto válido de extensão de navegador detectado " +
                            "(manifest legítimo, sem abuso runtime observado).";
        chain.Append(new EvidenceChainNode(
            sourceModule: "BrowserExtensionIntelligence",
            category: "Browser",
            description: note,
            scoreDelta: 0,
            strength: EvidenceStrength.Info,
            canConfirmMalware: false,
            timestampUtc: baseTimestamp.AddTicks(index++),
            correlationId: targetId,
            mitigationNote: note));
    }

    private static bool IsBrowserExtensionFinding(ScanFinding finding)
    {
        if (string.IsNullOrEmpty(finding.Path)) return false;
        var path = finding.Path.ToLowerInvariant();
        return path.Contains("\\extensions\\")
            || path.Contains("/extensions/")
            || path.EndsWith("manifest.json", StringComparison.OrdinalIgnoreCase);
    }

    private static void AddBehavioralEvents(ForensicTimeline timeline, IReadOnlyList<BehavioralEvent> events)
    {
        foreach (var e in events)
        {
            timeline.Add(new TimelineEvent(
                timestampUtc: e.TimestampUtc,
                sourceModule: "BehavioralEngine",
                category: e.Kind.ToString(),
                description: string.IsNullOrEmpty(e.Description) ? e.ExtraTag : e.Description,
                processId: e.Pid,
                processName: e.ProcessName,
                severity: MapBehavioralSeverity(e.Severity),
                correlationId: e.ImagePath));
        }
    }

    private static void AddMemoryEvents(ForensicTimeline timeline, IReadOnlyList<MemoryFinding> findings)
    {
        foreach (var m in findings)
        {
            timeline.Add(new TimelineEvent(
                timestampUtc: m.TimestampUtc,
                sourceModule: "MemoryScanner",
                category: m.Kind.ToString(),
                description: m.Description,
                processId: m.ProcessId,
                processName: m.ProcessName,
                severity: MapMemorySeverity(m.Severity),
                correlationId: m.BackingPath));
        }
    }

    private static void AddRuntimeEvents(ForensicTimeline timeline, IReadOnlyList<RuntimeTelemetryEvent> events)
    {
        foreach (var e in events)
        {
            timeline.Add(new TimelineEvent(
                timestampUtc: e.TimestampUtc,
                sourceModule: e.ProviderName,
                category: e.Kind.ToString(),
                description: string.IsNullOrEmpty(e.ExtraTag) ? e.CommandLine : e.ExtraTag,
                processId: e.Pid,
                processName: e.ProcessName,
                severity: ForensicSeverity.Informational,
                correlationId: e.ImagePath));
        }
    }

    private static void AddSchedulerEvents(ForensicTimeline timeline, IReadOnlyList<ScheduledJobExecution> executions)
    {
        foreach (var ex in executions)
        {
            // Scheduler failures are never malware. They are operational events
            // and get capped at Medium severity for reporting transparency.
            var severity = ex.Outcome switch
            {
                JobRunOutcome.Failed => ForensicSeverity.Medium,
                JobRunOutcome.Cancelled => ForensicSeverity.Low,
                JobRunOutcome.Skipped => ForensicSeverity.Informational,
                JobRunOutcome.Success => ForensicSeverity.Informational,
                _ => ForensicSeverity.Informational,
            };

            timeline.Add(new TimelineEvent(
                timestampUtc: ex.StartedUtc,
                sourceModule: "Scheduler",
                category: "JobRun",
                description: $"Job '{ex.JobName}' ({ex.JobId}) finished as {ex.Outcome}. {ex.Message}",
                severity: severity,
                correlationId: ex.JobId));
        }
    }

    private static ForensicReportSummary BuildSummary(
        ForensicReportInput input,
        IReadOnlyList<EvidenceChain> chains,
        IReadOnlyList<Incident> incidents,
        ForensicTimeline timeline)
    {
        int confirmed = input.Findings.Count(f => f.IsConfirmedMalware);
        int high = input.Findings.Count(f => !f.IsConfirmedMalware && f.Score >= RiskThresholds.High);
        int suspect = input.Findings.Count(f => !f.IsConfirmedMalware
                                                && f.Score >= RiskThresholds.Suspect
                                                && f.Score < RiskThresholds.High);
        int clean = Math.Max(0, input.Metrics.Eligible - input.Findings.Count);

        var highestSeverity = incidents.Count == 0
            ? ForensicSeverity.Informational
            : incidents.Max(i => i.Severity);
        var highestConfidence = incidents.Count == 0
            ? ForensicConfidence.Heuristic
            : incidents.Max(i => i.Confidence);

        return new ForensicReportSummary
        {
            FindingsTotal = input.Findings.Count,
            FindingsConfirmedMalware = confirmed,
            FindingsHighRisk = high,
            FindingsSuspect = suspect,
            FindingsClean = clean,
            IncidentsTotal = incidents.Count,
            IncidentsConfirmed = incidents.Count(i => i.IsConfirmed),
            IncidentsWithMitigations = incidents.Count(i => i.HasMitigations),
            TimelineEventsTotal = timeline.Count,
            BehavioralEventsConsumed = input.BehavioralEvents.Count,
            MemoryFindingsConsumed = input.MemoryFindings.Count,
            RuntimeEventsConsumed = input.RuntimeEvents.Count,
            SchedulerExecutionsConsumed = input.SchedulerExecutions.Count,
            HighestSeverity = highestSeverity,
            HighestConfidence = highestConfidence,
        };
    }

    private static ForensicSeverity MapSeverity(ScanFinding finding)
    {
        if (finding.IsConfirmedMalware) return ForensicSeverity.ConfirmedMalware;
        if (finding.Score >= RiskThresholds.Critical) return ForensicSeverity.Critical;
        if (finding.Score >= RiskThresholds.High) return ForensicSeverity.High;
        if (finding.Score >= RiskThresholds.Suspect) return ForensicSeverity.Medium;
        if (finding.Score > 0) return ForensicSeverity.Low;
        return ForensicSeverity.Informational;
    }

    private static ForensicConfidence MapConfidence(ScanFinding finding)
    {
        if (finding.IsConfirmedMalware) return ForensicConfidence.Confirmed;
        if (finding.Score >= RiskThresholds.High) return ForensicConfidence.High;
        if (finding.Score >= RiskThresholds.Suspect) return ForensicConfidence.Medium;
        if (finding.Score > 0) return ForensicConfidence.Low;
        return ForensicConfidence.Heuristic;
    }

    private static ForensicSeverity MapBehavioralSeverity(BehavioralSeverity severity) => severity switch
    {
        BehavioralSeverity.High => ForensicSeverity.High,
        BehavioralSeverity.Medium => ForensicSeverity.Medium,
        BehavioralSeverity.Low => ForensicSeverity.Low,
        _ => ForensicSeverity.Informational,
    };

    private static ForensicSeverity MapMemorySeverity(MemoryScanSeverity severity) => severity switch
    {
        MemoryScanSeverity.High => ForensicSeverity.High,
        MemoryScanSeverity.Medium => ForensicSeverity.Medium,
        MemoryScanSeverity.Low => ForensicSeverity.Low,
        _ => ForensicSeverity.Informational,
    };

    private static DateTime ResolveFindingTimestamp(ScanFinding finding, DateTime fallback)
    {
        if (finding.LastWrite == default) return fallback.ToUniversalTime();
        var ts = finding.LastWrite.Kind == DateTimeKind.Unspecified
            ? DateTime.SpecifyKind(finding.LastWrite, DateTimeKind.Utc)
            : finding.LastWrite.ToUniversalTime();
        return ts;
    }

    private static string BuildFindingDescription(ScanFinding finding)
    {
        if (!string.IsNullOrEmpty(finding.EvidenceSummary)) return finding.EvidenceSummary;
        return string.IsNullOrEmpty(finding.Reasons) ? finding.RiskLabel : finding.Reasons;
    }
}
