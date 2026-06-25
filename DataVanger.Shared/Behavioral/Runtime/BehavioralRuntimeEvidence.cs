using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Behavioral.Runtime;

/// <summary>
/// A single piece of runtime behavioral evidence produced by the
/// Behavioral Engine Runtime Binding (Phase 2 / Step 06).
///
/// CRITICAL anti-false-positive guarantees (enforced by design):
///   - This object is EVIDENCE ONLY. It is clearly labelled as runtime
///     behavioral evidence, never a confirmed verdict.
///   - <see cref="Severity"/> tops out at HighRisk; there is no path to
///     ConfirmedMalware through this type.
///   - <see cref="IsConfirmedMalware"/> is a hard-coded constant
///     <c>false</c> so that no scoring, aggregation, or rule can ever
///     flip behavioral evidence into a confirmation.
///   - Generating evidence NEVER quarantines, kills, suspends, blocks, or
///     injects. It is descriptive output for reporting/health only.
/// </summary>
public sealed class BehavioralRuntimeEvidence
{
    private static readonly IReadOnlyList<string> EmptyIndicators = Array.Empty<string>();

    /// <summary>Name of the module that produced this evidence.</summary>
    public string SourceModule { get; init; } = "BehavioralRuntimeBinding";

    /// <summary>Stable identifier of the rule that matched (e.g. <c>BRB-R1</c>).</summary>
    public string RuleId { get; init; } = string.Empty;

    /// <summary>Human-readable rule name.</summary>
    public string RuleName { get; init; } = string.Empty;

    public BehavioralRuntimeSeverity Severity { get; init; } = BehavioralRuntimeSeverity.Informational;

    public BehavioralRuntimeConfidence Confidence { get; init; } = BehavioralRuntimeConfidence.Low;

    /// <summary>
    /// Conservative, bounded score contribution. Guidance only — score
    /// can NEVER, by itself, produce ConfirmedMalware.
    /// </summary>
    public int Score { get; init; }

    public DateTimeOffset TimestampUtc { get; init; } = DateTimeOffset.UtcNow;

    public int? ProcessId { get; init; }
    public string? ProcessName { get; init; }
    public string? ProcessPath { get; init; }
    public string? ParentProcessName { get; init; }
    public string? ParentProcessPath { get; init; }

    /// <summary>Indicator tags that contributed to this evidence.</summary>
    public IReadOnlyList<string> Indicators { get; init; } = EmptyIndicators;

    /// <summary>Plain-language explanation of the observed behavior chain.</summary>
    public string Explanation { get; init; } = string.Empty;

    /// <summary>
    /// Conservative recommended action. NEVER an automatic destructive
    /// action — at most "review" / "investigate" guidance.
    /// </summary>
    public string RecommendedAction { get; init; } = "Review the activity. Runtime behavioral evidence only — does not confirm malware.";

    /// <summary>Explicit anti-false-positive note carried with the evidence.</summary>
    public string AntiFalsePositiveNote { get; init; } =
        "Runtime behavioral evidence only. This does NOT confirm malware and must not, by itself, trigger quarantine or any destructive action.";

    /// <summary>
    /// HARD INVARIANT: runtime behavioral evidence is never a confirmation.
    /// This is a constant so it cannot be overridden by any code path.
    /// </summary>
    public bool IsConfirmedMalware => false;
}
