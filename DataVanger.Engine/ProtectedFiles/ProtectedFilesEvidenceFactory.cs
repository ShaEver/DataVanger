using System;
using System.Collections.Generic;
using DataVanger.Shared.ProtectedFiles;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Engine.ProtectedFiles;

/// <summary>
/// Converts a scored activity state into
/// <see cref="ProtectedFilesActivityEvidence"/> and (optionally) into a
/// reporting-compatible <see cref="RuntimeSecurityEvent"/> (Phase 2 /
/// Step 07).
///
/// Evidence is always labelled as protected-file activity evidence and
/// never as a confirmation. The factory has no remediation authority.
/// </summary>
public sealed class ProtectedFilesEvidenceFactory
{
    public const string SourceModule = "ProtectedFilesActivityMonitor";

    private const int MaxTransitionsInEvidence = 5;

    public ProtectedFilesActivityEvidence Create(
        ProtectedFilesActivityState state,
        ActivityScore score,
        SafeResponse response,
        DateTimeOffset nowUtc)
    {
        var (ruleId, ruleName) = ResolveRule(score, state);

        var transitions = state.MutationProfile.TopTransitions(MaxTransitionsInEvidence);
        var recovery = new List<string>(state.RecoveryIndicators);

        var explanation = BuildExplanation(state, score, nowUtc);

        return new ProtectedFilesActivityEvidence
        {
            SourceModule = SourceModule,
            RuleId = ruleId,
            RuleName = ruleName,
            Severity = score.Level,
            Confidence = score.Confidence,
            Score = score.Total,
            TimestampUtc = nowUtc,
            ProcessId = state.ProcessId,
            ProcessName = state.ProcessName,
            ProcessPath = state.ProcessImagePath,
            FolderRoot = state.PrimaryProtectedFolderRoot,
            FileCount = state.ModificationWindow.CountInWindow(nowUtc),
            RenameCount = state.RenameWindow.CountInWindow(nowUtc),
            DistinctDirectoryCount = state.MutationProfile.DistinctDirectoryCount,
            TimeWindowSeconds = (nowUtc - state.FirstSeenUtc).TotalSeconds,
            TopExtensionTransitions = transitions,
            RecoveryIndicators = recovery,
            Reasons = score.Reasons,
            Indicators = score.Indicators,
            Explanation = explanation,
            ResponseMode = response.ModeLabel,
            RecommendedAction = response.RecommendedAction,
        };
    }

    /// <summary>
    /// Builds a reporting-compatible telemetry event from activity
    /// evidence. The event is sourced as
    /// <see cref="RuntimeEventSource.AntiRansomware"/> and categorized as
    /// <see cref="RuntimeEventCategory.RansomwareSuspicion"/> so existing
    /// reporting/forensics sinks can carry it WITHOUT any rewrite. It
    /// carries no quarantine/confirmation flags.
    /// </summary>
    public RuntimeSecurityEvent ToRuntimeEvent(ProtectedFilesActivityEvidence evidence)
    {
        var meta = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["protectedfiles.rule_id"] = evidence.RuleId,
            ["protectedfiles.rule_name"] = evidence.RuleName,
            ["protectedfiles.severity"] = evidence.Severity.ToString(),
            ["protectedfiles.confidence"] = evidence.Confidence.ToString(),
            ["protectedfiles.score"] = evidence.Score.ToString(),
            ["protectedfiles.file_count"] = evidence.FileCount.ToString(),
            ["protectedfiles.rename_count"] = evidence.RenameCount.ToString(),
            ["protectedfiles.distinct_directories"] = evidence.DistinctDirectoryCount.ToString(),
            ["protectedfiles.is_confirmed_malware"] = "false",
            ["protectedfiles.anti_fp_note"] = evidence.AntiFalsePositiveNote,
        };
        if (!string.IsNullOrEmpty(evidence.ProcessPath)) meta["protectedfiles.process_path"] = evidence.ProcessPath!;
        if (!string.IsNullOrEmpty(evidence.FolderRoot)) meta["protectedfiles.folder_root"] = evidence.FolderRoot!;
        if (evidence.TopExtensionTransitions.Count > 0) meta["protectedfiles.transitions"] = string.Join(";", evidence.TopExtensionTransitions);
        if (evidence.RecoveryIndicators.Count > 0) meta["protectedfiles.recovery_indicators"] = string.Join(",", evidence.RecoveryIndicators);
        if (evidence.Indicators.Count > 0) meta["protectedfiles.indicators"] = string.Join(",", evidence.Indicators);

        return new RuntimeSecurityEvent
        {
            Source = RuntimeEventSource.AntiRansomware,
            Category = RuntimeEventCategory.RansomwareSuspicion,
            // Telemetry severity is conservatively mapped and never used as
            // a verdict by the pipeline.
            Severity = MapSeverity(evidence.Severity),
            Title = $"Protected-file activity evidence: {evidence.RuleName}",
            Description = evidence.Explanation,
            ProcessId = evidence.ProcessId,
            ProcessName = evidence.ProcessName,
            SubjectPath = evidence.FolderRoot ?? evidence.ProcessPath,
            TimestampUtc = evidence.TimestampUtc,
            Metadata = meta,
        };
    }

    private static (string ruleId, string ruleName) ResolveRule(ActivityScore score, ProtectedFilesActivityState state)
    {
        // Pick the most representative rule id for the dominant signal.
        if (state.HasRecoveryIndicators)
            return ("PFA-R5", "Recovery-protection indicator observed");
        if (state.MutationProfile.SuspiciousTransitionCount > 0)
            return ("PFA-R3", "Suspicious extension transition activity");
        if (state.RenameWindow.TotalRecorded >= state.ModificationWindow.TotalRecorded && state.RenameWindow.TotalRecorded > 0)
            return ("PFA-R2", "High-volume file rename activity");
        return ("PFA-R1", "High-volume protected-file activity");
    }

    private static string BuildExplanation(ProtectedFilesActivityState state, ActivityScore score, DateTimeOffset nowUtc)
    {
        var who = state.ProcessName ?? state.ProcessImagePath ?? "an unidentified process";
        var folder = state.PrimaryProtectedFolderRoot is { Length: > 0 } f ? $" under {f}" : string.Empty;
        var reasons = score.Reasons.Count > 0 ? " " + string.Join(" ", score.Reasons) : string.Empty;
        return $"Abnormal protected-file activity (level {score.Level}, score {score.Total}) attributed to {who}{folder}.{reasons} " +
               "Protected-file activity evidence only — this does NOT confirm malware and no automatic action was taken.";
    }

    private static RuntimeEventSeverity MapSeverity(ProtectedFilesActivitySeverity severity) => severity switch
    {
        ProtectedFilesActivitySeverity.ProtectedActivitySuspected => RuntimeEventSeverity.High,
        ProtectedFilesActivitySeverity.HighRisk => RuntimeEventSeverity.High,
        ProtectedFilesActivitySeverity.Suspicious => RuntimeEventSeverity.Medium,
        ProtectedFilesActivitySeverity.Low => RuntimeEventSeverity.Low,
        _ => RuntimeEventSeverity.Informational,
    };
}
