using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core.Domain;
using DataVanger.Engine.DeepScan;

namespace DataVanger.Engine.DeepScan.Stages;

/// <summary>
/// Normalisation stage. Builds a <see cref="ScanTarget"/> for in-memory
/// content sources (which arrive without a real <see cref="FileInfo"/>) and
/// fast-paths obviously empty / oversized payloads. Cheap; runs synchronously.
/// </summary>
public sealed class NormalizationStage : IPipelineStage
{
    public string Name => "Normalize";

    public Task<StageResult> ExecuteAsync(ScanWorkItem item, DeepScanContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        context.Telemetry.IncNormalized();

        if (item.Target is null && item.Source is MemoryContentSource mem)
        {
            // Synthesise a phantom FileInfo so existing ScanTarget consumers keep working.
            var phantomPath = Path.Combine(Path.GetTempPath(), $"deepscan-{item.Id}-{Path.GetFileName(mem.LogicalPath)}");
            item.Target = new ScanTarget(new FileInfo(phantomPath));
        }

        if (item.Source.Length == 0)
        {
            item.Disposition = WorkItemDisposition.Skipped;
            item.DispositionReason = "empty content";
            context.Telemetry.IncSkipped();
            return Task.FromResult(StageResult.Skip);
        }

        if (context.Profile.MaxFileBytes > 0 && item.Source.Length > context.Profile.MaxFileBytes)
        {
            item.Disposition = WorkItemDisposition.Skipped;
            item.DispositionReason = $"file exceeds MaxFileBytes ({context.Profile.MaxFileBytes:N0})";
            context.Telemetry.IncSkipped();
            return Task.FromResult(StageResult.Skip);
        }

        return Task.FromResult(StageResult.Continue);
    }
}
