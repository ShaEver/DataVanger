using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Classification;
using DataVanger.Core;
using DataVanger.Engine.DeepScan;

namespace DataVanger.Engine.DeepScan.Stages;

/// <summary>
/// Applies the project's anti-false-positive clamp to the work item's
/// aggregated score and decides whether the item is worth reporting.
///
/// We deliberately do not call <see cref="ThreatClassificationPolicy"/> with a
/// full <see cref="ScanFinding"/> here — that lives in the reporting stage
/// where the finding is assembled. The job of THIS stage is to keep heuristics
/// from inflating into <c>Critical</c> on their own.
/// </summary>
public sealed class ClassificationStage : IPipelineStage
{
    public string Name => "Classification";

    public Task<StageResult> ExecuteAsync(ScanWorkItem item, DeepScanContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        bool hasConfirmed = item.KnownMalicious
            || item.Evidence.Any(e => e.CanConfirmMalware || e.Strength == EvidenceStrength.Confirmed);

        if (!hasConfirmed && item.Score >= RiskThresholds.Critical)
        {
            item.Score = RiskThresholds.High;
            item.AddEvidence(new Evidence
            {
                Category = "Engine",
                Description = "Score limitado a HighRisk: heurísticas sozinhas não confirmam malware",
                ScoreDelta = 0,
                Strength = EvidenceStrength.Info,
            });
        }

        int reportThreshold = context.ScanContext.Settings.MinScoreToReport;
        if (!hasConfirmed && item.Score < reportThreshold)
        {
            item.Disposition = WorkItemDisposition.Skipped;
            item.DispositionReason ??= "below report threshold";
            context.Telemetry.IncSkipped();
            return Task.FromResult(StageResult.Skip);
        }

        return Task.FromResult(StageResult.Continue);
    }
}
