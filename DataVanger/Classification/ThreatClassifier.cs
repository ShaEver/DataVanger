using System.Collections.Generic;
using System.Linq;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;

namespace DataVanger.Classification;

/// <summary>
/// Default <see cref="IThreatClassifier"/> implementation.
///
/// Layering note:
///   The legacy <see cref="ThreatClassificationPolicy"/> static class remains
///   the canonical, simple verdict path used by UI bindings and existing
///   tests. This class wraps it and adds the evidence-aware overload that
///   produces a richer <see cref="ThreatVerdict"/>.
///
///   Keeping both paths consistent is enforced by routing the legacy method
///   here and by reusing <see cref="AntiFalsePositivePolicy"/> on every branch.
/// </summary>
public sealed class ThreatClassifier : IThreatClassifier
{
    public ThreatClass Classify(ScanFinding finding) =>
        ThreatClassificationPolicy.Classify(finding);

    public bool AllowsAutomaticAction(ScanFinding finding) =>
        ThreatClassificationPolicy.AllowsAutomaticAction(finding);

    public ThreatVerdict Classify(ScanFinding finding, IReadOnlyList<Evidence> evidence, ScanContext context)
    {
        bool confirmed = AntiFalsePositivePolicy.IsConfirmed(finding, evidence);
        int score = AntiFalsePositivePolicy.ClampToHighRiskWhenUnconfirmed(finding.Score, finding, evidence);

        ThreatClass threatClass;
        DetectionConfidence confidence;
        SeverityLevel severity;

        if (confirmed)
        {
            threatClass = ThreatClass.ConfirmedMalware;
            confidence = DetectionConfidence.Confirmed;
            severity = SeverityLevel.Confirmed;
        }
        else if (score >= RiskThresholds.High)
        {
            threatClass = ThreatClass.HighRisk;
            confidence = DetectionConfidence.High;
            severity = SeverityLevel.HighRisk;
        }
        else if (score >= RiskThresholds.Suspect)
        {
            threatClass = ThreatClass.Suspect;
            confidence = DetectionConfidence.Medium;
            severity = SeverityLevel.Suspicious;
        }
        else
        {
            threatClass = ThreatClass.Clean;
            confidence = DetectionConfidence.None;
            severity = SeverityLevel.Clean;
        }

        return new ThreatVerdict
        {
            ThreatClass = threatClass,
            Severity = severity,
            Confidence = confidence,
            Score = score,
            Evidence = evidence,
            Explanation = BuildExplanation(threatClass, evidence, finding),
            RecommendedAction = ThreatClassificationPolicy.RecommendedAction(finding),
        };
    }

    private static string BuildExplanation(ThreatClass threatClass, IReadOnlyList<Evidence> evidence, ScanFinding finding)
    {
        if (evidence.Count == 0)
        {
            return string.IsNullOrWhiteSpace(finding.Reasons) ? "Sem motivo específico" : finding.Reasons;
        }

        var ordered = evidence
            .OrderByDescending(e => e.Strength)
            .ThenByDescending(e => e.ScoreDelta)
            .Take(threatClass == ThreatClass.ConfirmedMalware ? 3 : 5)
            .Select(e => e.ToString());
        return string.Join("; ", ordered);
    }
}
