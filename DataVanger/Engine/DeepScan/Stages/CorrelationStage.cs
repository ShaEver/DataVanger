using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core;
using DataVanger.Engine.DeepScan;

namespace DataVanger.Engine.DeepScan.Stages;

/// <summary>
/// Multi-evidence correlation. Combines weak signals into a single richer
/// finding when several independent categories agree. We do NOT promote
/// anything to <see cref="EvidenceStrength.Confirmed"/> here — that remains
/// the exclusive privilege of cryptographic evidence (hash hits, signed YARA).
/// </summary>
public sealed class CorrelationStage : IPipelineStage
{
    public string Name => "Correlation";

    public Task<StageResult> ExecuteAsync(ScanWorkItem item, DeepScanContext context, CancellationToken cancellationToken)
    {
        if (!context.Profile.CorrelateEvidence) return Task.FromResult(StageResult.Continue);
        cancellationToken.ThrowIfCancellationRequested();
        if (item.KnownMalicious) return Task.FromResult(StageResult.Continue);

        int distinctCategories = item.Evidence
            .Where(e => e.ScoreDelta > 0)
            .Select(e => e.Category)
            .Distinct(System.StringComparer.OrdinalIgnoreCase)
            .Count();

        if (distinctCategories >= 3)
        {
            // Add a small, transparent correlation bonus. The anti-FP clamp
            // downstream still prevents the verdict from crossing into Critical.
            item.AddEvidence(new Evidence
            {
                Category = "Correlation",
                Description = $"Múltiplos sinais correlacionados ({distinctCategories} categorias)",
                ScoreDelta = 2,
                Strength = EvidenceStrength.Medium,
            });
        }
        return Task.FromResult(StageResult.Continue);
    }
}
