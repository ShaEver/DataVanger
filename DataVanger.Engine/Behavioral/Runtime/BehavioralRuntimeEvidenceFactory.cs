using System;
using System.Collections.Generic;
using DataVanger.Shared.Behavioral.Runtime;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Engine.Behavioral.Runtime;

/// <summary>
/// Converts conservative rule matches into <see cref="BehavioralRuntimeEvidence"/>
/// and (optionally) into reporting-compatible
/// <see cref="RuntimeSecurityEvent"/> telemetry (Phase 2 / Step 06).
///
/// Evidence is always labelled as runtime behavioral evidence and never
/// as a confirmation. The factory has no remediation authority.
/// </summary>
public sealed class BehavioralRuntimeEvidenceFactory
{
    public const string SourceModule = "BehavioralRuntimeBinding";

    public BehavioralRuntimeEvidence Create(
        string ruleId,
        string ruleName,
        BehavioralRuntimeSeverity severity,
        BehavioralRuntimeConfidence confidence,
        int score,
        BehavioralRuntimeObservation observation,
        string? parentProcessName,
        string? parentProcessPath,
        IReadOnlyList<string> indicators,
        string explanation,
        string? recommendedAction = null,
        string? antiFalsePositiveNote = null)
    {
        return new BehavioralRuntimeEvidence
        {
            SourceModule = SourceModule,
            RuleId = ruleId,
            RuleName = ruleName,
            Severity = severity,
            Confidence = confidence,
            Score = score,
            TimestampUtc = observation.TimestampUtc,
            ProcessId = observation.ProcessId,
            ProcessName = observation.ProcessName,
            ProcessPath = observation.ImagePath,
            ParentProcessName = parentProcessName,
            ParentProcessPath = parentProcessPath,
            Indicators = indicators ?? Array.Empty<string>(),
            Explanation = explanation,
            RecommendedAction = recommendedAction
                ?? "Review the activity. Runtime behavioral evidence only — does not confirm malware.",
            AntiFalsePositiveNote = antiFalsePositiveNote
                ?? "Runtime behavioral evidence only. This does NOT confirm malware and must not, by itself, trigger quarantine or any destructive action.",
        };
    }

    /// <summary>
    /// Builds a reporting-compatible telemetry event from behavioral
    /// evidence. The event is sourced as <see cref="RuntimeEventSource.BehavioralEngine"/>
    /// and categorized as <see cref="RuntimeEventCategory.DetectionEvidence"/>
    /// so existing reporting/forensics sinks can carry it WITHOUT any
    /// rewrite. It carries no quarantine/confirmation flags.
    /// </summary>
    public RuntimeSecurityEvent ToRuntimeEvent(BehavioralRuntimeEvidence evidence)
    {
        var meta = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["behavioral.rule_id"] = evidence.RuleId,
            ["behavioral.rule_name"] = evidence.RuleName,
            ["behavioral.severity"] = evidence.Severity.ToString(),
            ["behavioral.confidence"] = evidence.Confidence.ToString(),
            ["behavioral.score"] = evidence.Score.ToString(),
            ["behavioral.is_confirmed_malware"] = "false",
            ["behavioral.anti_fp_note"] = evidence.AntiFalsePositiveNote,
        };
        if (!string.IsNullOrEmpty(evidence.ProcessPath)) meta["behavioral.process_path"] = evidence.ProcessPath!;
        if (!string.IsNullOrEmpty(evidence.ParentProcessName)) meta["behavioral.parent_process"] = evidence.ParentProcessName!;
        if (evidence.Indicators.Count > 0) meta["behavioral.indicators"] = string.Join(",", evidence.Indicators);

        return new RuntimeSecurityEvent
        {
            Source = RuntimeEventSource.BehavioralEngine,
            Category = RuntimeEventCategory.DetectionEvidence,
            // Telemetry severity is conservatively mapped and never used as
            // a verdict by the pipeline.
            Severity = MapSeverity(evidence.Severity),
            Title = $"Behavioral runtime evidence: {evidence.RuleName}",
            Description = evidence.Explanation,
            ProcessId = evidence.ProcessId,
            ProcessName = evidence.ProcessName,
            SubjectPath = evidence.ProcessPath,
            TimestampUtc = evidence.TimestampUtc,
            Metadata = meta,
        };
    }

    private static RuntimeEventSeverity MapSeverity(BehavioralRuntimeSeverity severity) => severity switch
    {
        BehavioralRuntimeSeverity.HighRisk => RuntimeEventSeverity.High,
        BehavioralRuntimeSeverity.Suspicious => RuntimeEventSeverity.Medium,
        BehavioralRuntimeSeverity.Low => RuntimeEventSeverity.Low,
        _ => RuntimeEventSeverity.Informational,
    };
}
