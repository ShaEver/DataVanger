using System.Threading;
using System.Threading.Tasks;
using DataVanger.Detection;
using DataVanger.Engine.DeepScan;

namespace DataVanger.Engine.DeepScan.Stages;

/// <summary>
/// Path-based pre-filter. Applies the same trust/exclusion taxonomy the legacy
/// engine used (see <see cref="PathTaxonomy"/>) so the deep pipeline never
/// wastes a worker hashing <c>C:\Windows\System32\notepad.exe</c>.
/// </summary>
public sealed class PreFilterStage : IPipelineStage
{
    public string Name => "PreFilter";

    public Task<StageResult> ExecuteAsync(ScanWorkItem item, DeepScanContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        context.Telemetry.IncPreFiltered();

        // Only on-disk items hit the path filters; in-memory archive entries
        // are always inspected because they cannot be "trusted by path".
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

        bool deep = context.ScanContext.Deep;
        if (!deep && PathTaxonomy.IsTrustedPath(fullLower))
        {
            item.Disposition = WorkItemDisposition.Skipped;
            item.DispositionReason = "trusted path";
            context.Telemetry.IncSkipped();
            return Task.FromResult(StageResult.Skip);
        }

        return Task.FromResult(StageResult.Continue);
    }
}
