using System.Collections.Generic;
using System.Linq;
using DataVanger.Core;

namespace DataVanger.Core.Domain;

/// <summary>
/// Output of <see cref="Abstractions.IThreatClassifier"/>.
///
/// A verdict is a self-contained, auditable record of how the classifier
/// reached its conclusion. The UI and report layer consume this directly
/// without re-running heuristics.
/// </summary>
public sealed class ThreatVerdict
{
    public ThreatClass ThreatClass { get; init; } = ThreatClass.Clean;
    public SeverityLevel Severity { get; init; } = SeverityLevel.Clean;
    public DetectionConfidence Confidence { get; init; } = DetectionConfidence.None;
    public int Score { get; init; }
    public string Explanation { get; init; } = "";
    public string RecommendedAction { get; init; } = "";
    public IReadOnlyList<Evidence> Evidence { get; init; } = System.Array.Empty<Evidence>();

    /// <summary>
    /// True when <see cref="ThreatClass"/> is <see cref="ThreatClass.ConfirmedMalware"/>.
    /// Convenience flag — the source of truth is <see cref="ThreatClass"/>.
    /// </summary>
    public bool IsConfirmedMalware => ThreatClass == ThreatClass.ConfirmedMalware;

    /// <summary>
    /// True when the engine is allowed to act automatically on this verdict.
    /// Anti-false-positive policy: only confirmed malware authorizes automatic action.
    /// </summary>
    public bool AllowsAutomaticAction => IsConfirmedMalware;

    public static ThreatVerdict Clean { get; } = new()
    {
        ThreatClass = ThreatClass.Clean,
        Severity = SeverityLevel.Clean,
        Confidence = DetectionConfidence.None,
        Explanation = "Nenhuma evidência relevante.",
        RecommendedAction = "Nenhuma ação"
    };
}
