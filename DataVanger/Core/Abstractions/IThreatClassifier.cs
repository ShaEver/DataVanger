using System.Collections.Generic;
using DataVanger.Core;
using DataVanger.Core.Domain;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// Single authoritative classifier for the project.
///
/// Implementations must enforce the anti-false-positive policy:
///   * <see cref="ThreatClass.ConfirmedMalware"/> requires confirmed evidence
///     (known-malicious hash OR confirmed signature/rule).
///   * Heuristic-only signals can produce Suspect or HighRisk but never
///     Confirmed, regardless of how large the accumulated score is.
/// </summary>
public interface IThreatClassifier
{
    /// <summary>
    /// Produces a structured verdict for the finding using the supplied
    /// evidence and scan context. The supplied evidence list is the source of
    /// truth — the classifier MUST NOT re-run heuristics.
    /// </summary>
    ThreatVerdict Classify(ScanFinding finding, IReadOnlyList<Evidence> evidence, ScanContext context);

    /// <summary>
    /// Coarse, finding-only classification kept for backward-compatibility
    /// with UI bindings that don't carry a <see cref="ScanContext"/>.
    /// </summary>
    ThreatClass Classify(ScanFinding finding);

    /// <summary>True only when the verdict authorizes automatic action.</summary>
    bool AllowsAutomaticAction(ScanFinding finding);
}
