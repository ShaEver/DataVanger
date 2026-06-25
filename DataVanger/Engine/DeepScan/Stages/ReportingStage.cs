using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.DeepScan;

namespace DataVanger.Engine.DeepScan.Stages;

/// <summary>
/// Terminal stage. Marks the work item as completed and hands it to the
/// orchestrator's findings list so it can be assembled into a
/// <see cref="DataVanger.Core.ScanFinding"/> later.
///
/// Kept deliberately tiny: report rendering, HTML/JSON serialisation and
/// quarantine triggering remain in <see cref="DataVanger.Core.ScanEngine"/>.
/// </summary>
public sealed class ReportingStage : IPipelineStage
{
    public string Name => "Report";

    public Task<StageResult> ExecuteAsync(ScanWorkItem item, DeepScanContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (item.Disposition == WorkItemDisposition.Pending) item.Disposition = WorkItemDisposition.Completed;
        if (item.Evidence.Count > 0)
        {
            context.AddFinding(item);
            context.Telemetry.IncFinding();
        }
        return Task.FromResult(StageResult.Continue);
    }
}
