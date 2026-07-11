namespace DataVanger.Core.Domain;

/// <summary>
/// Confidence level a module/classifier attributes to a verdict.
///
/// Confidence is intentionally separate from <see cref="EvidenceStrength"/>:
/// strength describes a single piece of evidence, confidence describes the
/// verdict produced after aggregating many pieces of evidence.
/// </summary>
public enum DetectionConfidence
{
    None,
    Low,
    Medium,
    High,
    Confirmed
}
