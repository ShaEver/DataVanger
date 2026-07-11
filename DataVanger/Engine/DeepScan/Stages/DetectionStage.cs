using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;
using PeStaticAnalyzer = DataVanger.Detection.PE.PeAnalyzer;
using DataVanger.Engine;
using DataVanger.Engine.DeepScan;

namespace DataVanger.Engine.DeepScan.Stages;

/// <summary>
/// Bridges the deep scan pipeline to the existing per-file
/// <see cref="DetectionPipeline"/>. Runs all registered detection modules and
/// folds their evidence into the work item's score. Bounded by
/// <see cref="DeepScanProfileSettings.PerFileTimeout"/> via a linked CTS so a
/// pathological module can never freeze a worker.
/// </summary>
public sealed class DetectionStage : IPipelineStage
{
    private readonly DetectionPipeline _detection;

    public DetectionStage(DetectionPipeline detection)
    {
        _detection = detection ?? throw new ArgumentNullException(nameof(detection));
    }

    public string Name => "Detection";

    public async Task<StageResult> ExecuteAsync(ScanWorkItem item, DeepScanContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (item.Target is null)
        {
            if (item.SniffedType == SniffedFileType.Pe)
            {
                try
                {
                    using var source = item.Source.OpenRead();
                    var peResult = PeStaticAnalyzer.Analyze(source, item.Source.LogicalPath);
                    foreach (var ev in peResult.Evidence) item.AddEvidence(ev);
                    if (peResult.HasHits) context.Telemetry.IncDetection();
                }
                catch (Exception ex)
                {
                    context.Telemetry.IncError();
                    context.Logger.ModuleFailure("PeStatic", item.Source.LogicalPath, ex);
                }
            }
            return StageResult.Continue;
        }

        using var perFile = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (context.Profile.PerFileTimeout > TimeSpan.Zero) perFile.CancelAfter(context.Profile.PerFileTimeout);

        try
        {
            var outcome = await _detection.AnalyzeAsync(item.Target, context.ScanContext, perFile.Token).ConfigureAwait(false);
            foreach (var ev in outcome.Evidence) item.AddEvidence(ev);
            context.Telemetry.IncDetection();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            context.Telemetry.IncTimeout();
            item.DispositionReason = "detection timeout";
            item.AddEvidence(new Evidence
            {
                Category = "Engine",
                Description = "Análise interrompida por timeout do perfil",
                ScoreDelta = 0,
                Strength = EvidenceStrength.Info,
            });
        }
        catch (Exception ex)
        {
            context.Telemetry.IncError();
            context.Logger.ModuleFailure("DetectionStage", item.Source.LogicalPath, ex);
        }
        return StageResult.Continue;
    }
}

