using System.Threading;
using System.Threading.Tasks;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// One step of the deep scan pipeline.
///
/// A stage receives a <see cref="ScanWorkItem"/> and the shared
/// <see cref="DeepScanContext"/>. It may mutate the work item, enqueue extra
/// items (archive expansion), or set <see cref="WorkItemDisposition"/> to
/// short-circuit the rest of the pipeline. Stages MUST honor the supplied
/// cancellation token and MUST NEVER throw — they should set the disposition
/// instead and return.
/// </summary>
public interface IPipelineStage
{
    string Name { get; }

    Task<StageResult> ExecuteAsync(ScanWorkItem item, DeepScanContext context, CancellationToken cancellationToken);
}

public enum StageResult
{
    /// <summary>Continue with the next stage.</summary>
    Continue,
    /// <summary>Skip the rest of the pipeline for this work item (mark it complete).</summary>
    Skip,
}
