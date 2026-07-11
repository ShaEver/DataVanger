using System.Collections.Generic;
using System.Linq;
using DataVanger.Core;
using DataVanger.Detection.PE;

namespace DataVanger.Classification;

/// <summary>
/// BETA 11E — evidence category model. Separates technical/informational
/// observations from genuinely actionable risk, on top of (and consistent with)
/// the 11C-stabilized recalibration helpers. This is a read-only classification
/// layer: it changes no score, threshold, or clamp.
/// </summary>
public enum EvidenceClass
{
    /// <summary>Relief, neutral, or descriptive evidence (ScoreDelta &lt;= 0 or Info).</summary>
    Informational,
    /// <summary>Common technical imports already capped/demoted by 11C (not actionable alone).</summary>
    Technical,
    /// <summary>Positive Low/Medium signals that raise suspicion but are not corroborating by themselves.</summary>
    Suspicious,
    /// <summary>A strong, structural/behavioral signal (e.g. RWX, packer, embedded payload, strong PE correlation).</summary>
    Actionable,
    /// <summary>Evidence that can confirm malware (known-malicious hash, confirmed YARA).</summary>
    Confirmed,
}

/// <summary>
/// Maps evidence to <see cref="EvidenceClass"/> and exposes the actionable-corroboration
/// predicate used by the trusted/system HighRisk gate. The predicate is intentionally
/// identical to the 11C-stabilized
/// <c>HasActionableEvidenceAfterTrustRecalibration</c> (confirmable OR severe-structural PE),
/// so 11E never weakens or alters the stabilized relief behavior.
/// </summary>
public static class EvidenceClassification
{
    public static EvidenceClass Classify(Evidence e)
    {
        if (e is null) return EvidenceClass.Informational;
        if (e.CanConfirmMalware || e.Strength == EvidenceStrength.Confirmed) return EvidenceClass.Confirmed;
        if (PeImportRecalibration.IsSevereStructuralEvidence(e)) return EvidenceClass.Actionable;
        if (e.ScoreDelta <= 0 || e.Strength == EvidenceStrength.Info) return EvidenceClass.Informational;
        if (PeImportRecalibration.IsCommonImportEvidence(e)) return EvidenceClass.Technical;
        return EvidenceClass.Suspicious;
    }

    /// <summary>True for evidence that corroborates HighRisk on its own (actionable or confirmed).</summary>
    public static bool IsActionable(Evidence e) => Classify(e) is EvidenceClass.Actionable or EvidenceClass.Confirmed;

    /// <summary>
    /// Whether the evidence set contains at least one actionable corroborating signal. Identical to
    /// the 11C-stabilized actionable predicate: a positive-score evidence that is confirmable or a
    /// severe/structural PE anomaly. Common imports and technical/informational metadata do NOT count.
    /// </summary>
    public static bool HasActionableCorroboration(IReadOnlyList<Evidence> evidence) =>
        evidence != null && evidence.Any(e =>
            e.ScoreDelta > 0
            && (e.CanConfirmMalware
                || e.Strength == EvidenceStrength.Confirmed
                || PeImportRecalibration.IsSevereStructuralEvidence(e)));
}
