namespace DataVanger.Core.Domain;

/// <summary>
/// Human-facing severity bucket for a verdict.
/// Maps 1:1 to <see cref="ThreatClass"/>; kept separate so future variants
/// (e.g. NeedsReview, Quarantined) can be added without disturbing the classifier.
/// </summary>
public enum SeverityLevel
{
    Clean = 0,
    Suspicious = 1,
    HighRisk = 2,
    Confirmed = 3,
}
