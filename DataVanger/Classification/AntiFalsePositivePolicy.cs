using System.Collections.Generic;
using System.Linq;
using DataVanger.Core;
using DataVanger.Core.Domain;

namespace DataVanger.Classification;

/// <summary>
/// Single source of truth for the project's anti-false-positive contract.
///
/// The rule, repeated here so reviewers find it on grep:
///
///     ConfirmedMalware REQUIRES confirmed evidence
///     (known malicious hash OR confirmed YARA rule OR trusted feed hit).
///     Heuristic-only signals can produce HighRisk/Suspect at most.
///
/// Centralising the check here means new evidence sources can be added
/// without re-deriving the rule in classifier, engine, report and UI.
/// </summary>
public static class AntiFalsePositivePolicy
{
    /// <summary>True when at least one piece of evidence is strong enough to confirm.</summary>
    public static bool HasConfirmedEvidence(IEnumerable<Evidence> evidence) =>
        evidence.Any(e => e.CanConfirmMalware || e.Strength == EvidenceStrength.Confirmed);

    /// <summary>True when the finding has confirmed evidence by any path.</summary>
    public static bool IsConfirmed(ScanFinding finding, IEnumerable<Evidence>? evidence = null)
    {
        if (finding.IsBlacklisted || finding.HasConfirmedSignature) return true;
        return evidence != null && HasConfirmedEvidence(evidence);
    }

    /// <summary>
    /// Clamps a score down to <see cref="RiskThresholds.High"/> when the
    /// finding has no confirmed evidence, regardless of how high heuristics
    /// pushed it.
    /// </summary>
    public static int ClampToHighRiskWhenUnconfirmed(int score, ScanFinding finding, IEnumerable<Evidence>? evidence = null)
    {
        if (IsConfirmed(finding, evidence)) return score;
        return score >= RiskThresholds.Critical ? RiskThresholds.High : score;
    }
}
