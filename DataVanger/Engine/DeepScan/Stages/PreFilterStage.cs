using System.Threading;
using System.Threading.Tasks;
using DataVanger.Detection;
using DataVanger.Engine.DeepScan;

namespace DataVanger.Engine.DeepScan.Stages;

/// <summary>
/// Path-based pre-filter. Only explicit operator exclusions can skip an on-disk
/// item; vendor or system-looking paths remain eligible for analysis.
/// </summary>
public sealed class PreFilterStage : IPipelineStage
{
    public string Name => "PreFilter";

    public Task<StageResult> ExecuteAsync(ScanWorkItem item, DeepScanContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        context.Telemetry.IncPreFiltered();

        // Only on-disk items hit explicit operator exclusions; in-memory archive
        // entries are always inspected.
        if (!item.Source.IsOnDisk) return Task.FromResult(StageResult.Continue);

        string fullLower = item.Source.LogicalPath.ToLowerInvariant();
        var settings = context.ScanContext.Settings;

        if (TargetDiscovery.IsExcludedPath(fullLower, settings))
        {
            item.Disposition = WorkItemDisposition.Skipped;
            item.DispositionReason = "excluded path";
            context.Telemetry.IncSkipped();
            return Task.FromResult(StageResult.Skip);
        }

        return Task.FromResult(StageResult.Continue);
    }
}
