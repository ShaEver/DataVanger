using System;
using System.Collections.Generic;
using DataVanger.Shared.ProtectedFiles;

namespace DataVanger.Engine.ProtectedFiles;

/// <summary>
/// Explainable scoring result produced by <see cref="ActivityScoringPolicy"/>.
/// Carries the conservative score, the resulting severity level, and a
/// human-readable reason list. It is EVIDENCE guidance only — it never
/// confirms malware.
/// </summary>
public sealed class ActivityScore
{
    public int Total { get; init; }
    public ProtectedFilesActivitySeverity Level { get; init; } = ProtectedFilesActivitySeverity.Informational;
    public ProtectedFilesActivityConfidence Confidence { get; init; } = ProtectedFilesActivityConfidence.Low;
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Indicators { get; init; } = Array.Empty<string>();

    /// <summary>Distinct scoring categories that contributed a positive score.</summary>
    public int ContributingCategories { get; init; }
}

/// <summary>
/// Conservative, explainable scoring policy for the Protected Files
/// Activity Monitor (Phase 2 / Step 07).
///
/// CRITICAL anti-false-positive guarantees:
///   - Output tops out at
///     <see cref="ProtectedFilesActivitySeverity.ProtectedActivitySuspected"/>
///     which is EVIDENCE ONLY — there is no ConfirmedMalware path.
///   - A single signal in isolation (volume only, rename only, recovery
///     label only, entropy only) is capped below the top level; reaching
///     <c>ProtectedActivitySuspected</c> REQUIRES multiple correlated
///     categories. This prevents one noisy signal from over-classifying.
///   - Scoring prefers explainable reasons over opaque thresholds.
/// </summary>
public sealed class ActivityScoringPolicy
{
    private readonly ProtectedFilesActivityOptions _options;

    public ActivityScoringPolicy(ProtectedFilesActivityOptions options)
    {
        _options = (options ?? ProtectedFilesActivityOptions.DevelopmentSafe()).WithSafeDefaults();
    }

    /// <summary>
    /// Scores the current state at the supplied time. Never throws.
    /// </summary>
    public ActivityScore Score(ProtectedFilesActivityState state, DateTimeOffset nowUtc)
    {
        if (state is null)
        {
            return new ActivityScore();
        }

        var reasons = new List<string>();
        var indicators = new List<string>();
        var total = 0;
        var categories = 0;

        // 1. Mutation volume.
        var liveMod = state.ModificationWindow.CountInWindow(nowUtc);
        if (liveMod >= _options.ModificationBurstThreshold)
        {
            var pts = 25 + (liveMod >= _options.ModificationBurstThreshold * 2 ? 10 : 0);
            total += pts; categories++;
            indicators.Add("mass-file-modification");
            reasons.Add($"High-volume file modification: {liveMod} modifications within {_options.ActivityWindow.TotalSeconds:0}s (threshold {_options.ModificationBurstThreshold}).");
        }

        // 2. Rename burst.
        var renameCount = state.RenameWindow.CountInWindow(nowUtc);
        if (renameCount >= _options.RenameBurstThreshold)
        {
            var pts = 25 + (renameCount >= _options.RenameBurstThreshold * 2 ? 10 : 0);
            total += pts; categories++;
            indicators.Add("mass-file-rename");
            reasons.Add($"High-volume file rename: {renameCount} renames within {_options.ActivityWindow.TotalSeconds:0}s (threshold {_options.RenameBurstThreshold}).");
        }

        // 3. Suspicious extension replacement.
        if (_options.EnableExtensionTransitionAnalysis)
        {
            var sus = state.MutationProfile.SuspiciousTransitionCount;
            if (sus >= _options.SuspiciousExtensionTransitionThreshold)
            {
                total += 30; categories++;
                indicators.Add("suspicious-extension-replacement");
                reasons.Add($"Suspicious extension transitions: {sus} document files changed to ransom-style/unknown extensions (threshold {_options.SuspiciousExtensionTransitionThreshold}).");
            }
            else if (sus >= 1)
            {
                total += 10;
                indicators.Add("extension-transition");
                reasons.Add($"Observed {sus} suspicious extension transition(s) (below burst threshold).");
            }
        }

        // 4. Protected folder activity.
        if (_options.EnableProtectedFolderMonitoring && state.HasProtectedActivity)
        {
            total += 15; categories++;
            indicators.Add("protected-folder-activity");
            reasons.Add($"Activity touched protected user folder(s): {state.PrimaryProtectedFolderRoot ?? "<protected>"}.");
        }

        // 5. Directory spread.
        var dirs = state.MutationProfile.DistinctDirectoryCount;
        if (dirs >= 20)
        {
            total += 20; categories++;
            indicators.Add("wide-directory-spread");
            reasons.Add($"Activity spread across {dirs} distinct directories.");
        }
        else if (dirs >= 8)
        {
            total += 10; categories++;
            indicators.Add("directory-spread");
            reasons.Add($"Activity spread across {dirs} distinct directories.");
        }

        // 6. Recovery-protection indicators (normalized labels only).
        if (_options.EnableRecoveryIndicatorLabels && state.HasRecoveryIndicators)
        {
            var labelCount = state.RecoveryIndicators.Count;
            var pts = Math.Min(30 + (labelCount - 1) * 5, 45);
            total += pts; categories++;
            foreach (var label in state.RecoveryIndicators) indicators.Add(label);
            reasons.Add($"Recovery-protection indicator label(s) observed (labels only, no commands): {string.Join(", ", state.RecoveryIndicators)}.");
        }

        // 7. Entropy delta (weak signal; gated).
        if (_options.EnableEntropySampling)
        {
            if (state.MutationProfile.ObservedEntropyIncrease)
            {
                total += 10;
                indicators.Add("entropy-increase");
                reasons.Add("Observed a ransomware-consistent entropy increase after mutation (weak signal).");
            }
            else if (state.MutationProfile.ObservedHighEntropy)
            {
                total += 5;
                indicators.Add("high-entropy");
                reasons.Add("Observed high-entropy content after mutation (weak signal).");
            }
        }

        // Map score → level, with the multi-category requirement for the top
        // level (prevents a single noisy signal from over-classifying).
        var level = MapLevel(total, categories);
        var confidence = MapConfidence(level, categories);

        return new ActivityScore
        {
            Total = total,
            Level = level,
            Confidence = confidence,
            Reasons = reasons,
            Indicators = indicators,
            ContributingCategories = categories,
        };
    }

    private static ProtectedFilesActivitySeverity MapLevel(int total, int categories)
    {
        if (total <= 7) return ProtectedFilesActivitySeverity.Informational;
        if (total <= 19) return ProtectedFilesActivitySeverity.Low;
        if (total <= 39) return ProtectedFilesActivitySeverity.Suspicious;

        if (total <= 69)
        {
            return categories >= 2
                ? ProtectedFilesActivitySeverity.HighRisk
                : ProtectedFilesActivitySeverity.Suspicious;
        }

        // Top label requires genuine correlation across >= 3 categories.
        return categories >= 3
            ? ProtectedFilesActivitySeverity.ProtectedActivitySuspected
            : ProtectedFilesActivitySeverity.HighRisk;
    }

    private static ProtectedFilesActivityConfidence MapConfidence(
        ProtectedFilesActivitySeverity level, int categories)
    {
        if (level == ProtectedFilesActivitySeverity.ProtectedActivitySuspected && categories >= 3)
            return ProtectedFilesActivityConfidence.High;
        if (level >= ProtectedFilesActivitySeverity.HighRisk && categories >= 2)
            return ProtectedFilesActivityConfidence.Medium;
        return ProtectedFilesActivityConfidence.Low;
    }
}
