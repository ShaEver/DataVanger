using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.DeepScan;

namespace DataVanger.Engine.DeepScan.Stages;

/// <summary>
/// Streaming SHA-256 stage. Honours <see cref="DeepScanProfileSettings.PerHashTimeout"/>
/// using a linked cancellation token so a stuck IO never blocks the worker for
/// longer than the configured budget.
/// </summary>
public sealed class HashingStage : IPipelineStage
{
    public string Name => "Hash";

    public async Task<StageResult> ExecuteAsync(ScanWorkItem item, DeepScanContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        using var hashCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (context.Profile.PerHashTimeout > TimeSpan.Zero) hashCts.CancelAfter(context.Profile.PerHashTimeout);

        try
        {
            await using var stream = item.Source.OpenRead();
            item.Sha256 = await StreamHasher.ComputeSha256Async(stream, context.Profile.MaxFileBytes, hashCts.Token).ConfigureAwait(false);
            if (item.Sha256 != null && item.Target != null) item.Target.Sha256 = item.Sha256;
            context.Telemetry.IncHashed();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Per-hash timeout: degrade gracefully, don't fail the scan.
            context.Telemetry.IncTimeout();
            item.DispositionReason = "hash timeout";
        }
        catch (System.Exception)
        {
            context.Telemetry.IncError();
        }
        return StageResult.Continue;
    }
}
