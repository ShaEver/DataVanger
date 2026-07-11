using System;
using System.Collections.Generic;

namespace DataVanger.Shared.ProtectedFiles;

/// <summary>
/// A single piece of protected-file activity evidence produced by the
/// Protected Files Activity Monitor (Phase 2 / Step 07).
///
/// CRITICAL anti-false-positive guarantees (enforced by design):
///   - This object is EVIDENCE ONLY. It is clearly labelled as
///     protected-file activity evidence, never a confirmed verdict.
///   - <see cref="Severity"/> tops out at ProtectedActivitySuspected;
///     there is no path to ConfirmedMalware through this type.
///   - <see cref="IsConfirmedMalware"/> is a hard-coded constant
///     <c>false</c> so that no scoring, aggregation, or rule can ever
///     flip activity evidence into a confirmation.
///   - Generating evidence NEVER quarantines, kills, suspends, blocks
///     writes, or injects. It is descriptive output for reporting/health
///     only.
/// </summary>
public sealed class ProtectedFilesActivityEvidence
{
    private static readonly IReadOnlyList<string> Empty = Array.Empty<string>();

    /// <summary>Name of the module that produced this evidence.</summary>
    public string SourceModule { get; init; } = "ProtectedFilesActivityMonitor";

    /// <summary>Stable identifier of the rule that matched (e.g. <c>PFA-R1</c>).</summary>
    public string RuleId { get; init; } = string.Empty;

    /// <summary>Human-readable rule name.</summary>
    public string RuleName { get; init; } = string.Empty;

    public ProtectedFilesActivitySeverity Severity { get; init; } = ProtectedFilesActivitySeverity.Informational;

    public ProtectedFilesActivityConfidence Confidence { get; init; } = ProtectedFilesActivityConfidence.Low;

    /// <summary>
    /// Conservative, bounded score contribution. Guidance only — score
    /// can NEVER, by itself, produce ConfirmedMalware.
    /// </summary>
    public int Score { get; init; }

    public DateTimeOffset TimestampUtc { get; init; } = DateTimeOffset.UtcNow;

    public int? ProcessId { get; init; }
    public string? ProcessName { get; init; }
    public string? ProcessPath { get; init; }

    /// <summary>Affected folder root (bounded sample; not a full file list).</summary>
    public string? FolderRoot { get; init; }

    /// <summary>Approximate count of affected files within the activity window.</summary>
    public int FileCount { get; init; }

    /// <summary>Approximate count of renamed files within the activity window.</summary>
    public int RenameCount { get; init; }

    /// <summary>Distinct directories touched within the activity window (bounded view).</summary>
    public int DistinctDirectoryCount { get; init; }

    /// <summary>The correlation time window, in seconds.</summary>
    public double TimeWindowSeconds { get; init; }

    /// <summary>Top extension transitions observed (bounded; e.g. <c>.docx-&gt;.locked</c>).</summary>
    public IReadOnlyList<string> TopExtensionTransitions { get; init; } = Empty;

    /// <summary>
    /// Normalized recovery-protection indicator labels (labels ONLY; the
    /// monitor never reconstructs or emits the underlying commands).
    /// </summary>
    public IReadOnlyList<string> RecoveryIndicators { get; init; } = Empty;

    /// <summary>Explainable reason list contributing to the score.</summary>
    public IReadOnlyList<string> Reasons { get; init; } = Empty;

    /// <summary>Indicator tags that contributed to this evidence.</summary>
    public IReadOnlyList<string> Indicators { get; init; } = Empty;

    /// <summary>Plain-language explanation of the observed activity.</summary>
    public string Explanation { get; init; } = string.Empty;

    /// <summary>Passive response mode label (e.g. <c>Passive</c> / <c>AlertOnly</c>).</summary>
    public string ResponseMode { get; init; } = "Passive";

    /// <summary>
    /// Conservative recommended action. NEVER an automatic destructive
    /// action — at most "review" / "investigate" guidance.
    /// </summary>
    public string RecommendedAction { get; init; } =
        "Review the activity. Protected-file activity evidence only — does not confirm malware.";

    /// <summary>Explicit anti-false-positive note carried with the evidence.</summary>
    public string AntiFalsePositiveNote { get; init; } =
        "Protected-file activity evidence only. This does NOT confirm malware and must not, by itself, trigger quarantine or any destructive action.";

    /// <summary>
    /// HARD INVARIANT: protected-file activity evidence is never a
    /// confirmation. This is a constant so it cannot be overridden by any
    /// code path.
    /// </summary>
    public bool IsConfirmedMalware => false;
}
