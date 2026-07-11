using System.Collections.Generic;
using System.Threading;
using DataVanger.Core;
using DataVanger.Core.Domain;

namespace DataVanger.Detection;

/// <summary>
/// Marks a target when its path matches a persistence-registry entry.
///
/// Persistence by itself is heuristic — many legitimate apps register
/// autostart — so this module never confirms malware. The score delta is
/// modest; the classifier escalates only when combined with other signals.
/// </summary>
public sealed class PersistenceDetectionModule : DetectionModuleBase
{
    public override string Name => "Persistence";
    public override DetectionModuleCapabilities Capabilities =>
        DetectionModuleCapabilities.NeedsPath | DetectionModuleCapabilities.PersistenceAware;

    public override bool Supports(ScanTarget target, ScanContext context) =>
        context.PersistenceExactPaths.Count > 0 || context.PersistenceBlob.Length > 0;

    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
    {
        string full = target.FullPathLower;
        bool exact = context.PersistenceExactPaths.Contains(full);
        bool blob = context.PersistenceBlob.Contains(full);
        if (!exact && !blob) return System.Array.Empty<Evidence>();

        target.IsPersistenceCandidate = true;

        bool userWritable = PathTaxonomy.IsUserWritableRiskPath(full);
        bool protectedWindows = PathTaxonomy.IsProtectedWindowsPath(full);
        int delta = (userWritable && !protectedWindows) ? 3 : 1;

        return new[]
        {
            new Evidence
            {
                Category = "Persistence",
                Description = "Persistência detectada",
                Strength = EvidenceStrength.Medium,
                ScoreDelta = delta,
            }
        };
    }
}
