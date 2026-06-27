using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;
using DataVanger.Engine.DeepScan.Stages;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Top-level driver for the Deep Scan Pipeline.
///
/// Responsibilities:
///   1. Build a bounded <see cref="Channel{T}"/> for work items (the queue
///      that connects discovery and the worker pool).
///   2. Spawn the discovery task and N parallel workers.
///   3. Apply the ordered list of <see cref="IPipelineStage"/> instances to
///      every work item until each stage either completes or short-circuits.
///   4. Propagate cancellation, enforce timeouts, expose telemetry.
///
/// The orchestrator owns no detection logic; new analyses plug in by adding
/// a stage to <see cref="BuildDefaultStages"/> (or a custom list passed via
/// <see cref="DeepScanOrchestratorOptions.Stages"/>). This is the seam future
/// modules (PE deep analysis, cloud reputation, ML scoring) will use.
/// </summary>
public sealed class DeepScanOrchestrator
{
    private readonly DeepScanOrchestratorOptions _options;

    public DeepScanOrchestrator(DeepScanOrchestratorOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public async Task<DeepScanResult> RunAsync(
        IEnumerable<string> roots,
        ScanContext scanContext,
        CancellationToken cancellationToken)
    {
        if (roots is null) throw new ArgumentNullException(nameof(roots));
        if (scanContext is null) throw new ArgumentNullException(nameof(scanContext));

        var profile = _options.Profile;
        var telemetry = _options.Telemetry ?? new DeepScanTelemetry();
        var logger = _options.Logger;

        using var throttle = new ScanThrottle(profile.MaxDegreeOfParallelism, profile.CpuThrottleDelayMs);

        // Bounded queue: discovery may wait for capacity, but worker-side
        // archive expansion must use non-blocking writes so workers never all
        // park while holding the only readers. This keeps memory bounded
        // without reintroducing the classic recursive-producer deadlock.
        var channel = Channel.CreateBounded<ScanWorkItem>(new BoundedChannelOptions(Math.Max(1, profile.WorkQueueCapacity))
        {
            SingleReader = false,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
        });

        // Overall-timeout CTS: when set, the whole scan stops gracefully when
        // the budget is exhausted. We link it with the caller's token so user
        // cancellation still wins.
        using var overallCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (profile.OverallTimeout > TimeSpan.Zero) overallCts.CancelAfter(profile.OverallTimeout);
        var token = overallCts.Token;

        var pending = new PendingWorkCounter();
        var context = new DeepScanContext(
            profile: profile,
            scanContext: scanContext,
            telemetry: telemetry,
            throttle: throttle,
            queueWriter: channel.Writer,
            modules: _options.Modules,
            logger: logger,
            pending: pending);

        var stages = _options.Stages;

        // Discovery is a dedicated background task so the worker pool starts
        // draining work as soon as the first file is enqueued.
        Task discoveryTask = Task.Run(async () =>
        {
            try
            {
                await _options.Discovery.DiscoverAsync(roots, channel.Writer, context, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { /* swallowed: status surfaces via telemetry */ }
            catch (Exception ex)
            {
                logger.Error("Discovery falhou", ex);
                context.Telemetry.IncError();
            }
            finally
            {
                pending.MarkDiscoveryDone();
            }
        }, token);

        // Sentinel task: once the pending counter drains AND discovery is done,
        // we complete the channel so workers see WaitToReadAsync return false.
        Task drainGate = Task.Run(async () =>
        {
            try { await pending.WaitForDrainAsync(token).ConfigureAwait(false); }
            catch (OperationCanceledException) { /* tearing down */ }
            finally { channel.Writer.TryComplete(); }
        }, token);

        // Workers run until the channel is completed AND drained. Each worker
        // owns its own loop; cancellation tears them down quickly without
        // touching shared state.
        var workers = new Task[Math.Max(1, profile.MaxDegreeOfParallelism)];
        for (int i = 0; i < workers.Length; i++)
        {
            workers[i] = Task.Run(() => WorkerLoopAsync(channel.Reader, context, stages, token), token);
        }

        try
        {
            await Task.WhenAll(workers).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { /* expected on cancellation */ }
        finally
        {
            // Make sure both auxiliary tasks observe completion.
            try { await discoveryTask.ConfigureAwait(false); } catch (System.Exception) { /* already logged */ }
            try { await drainGate.ConfigureAwait(false); } catch (System.Exception) { /* already logged */ }
        }

        return new DeepScanResult
        {
            Items = context.Findings.ToArray(),
            Telemetry = telemetry.Snapshot(),
            Cancelled = cancellationToken.IsCancellationRequested,
            TimedOut = token.IsCancellationRequested && !cancellationToken.IsCancellationRequested,
        };
    }

    private static async Task WorkerLoopAsync(
        ChannelReader<ScanWorkItem> reader,
        DeepScanContext context,
        IReadOnlyList<IPipelineStage> stages,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            bool more;
            try { more = await reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            if (!more) return;

            while (reader.TryRead(out var item))
            {
                context.Telemetry.DecQueueDepth();
                try
                {
                    await ProcessOneAsync(item, context, stages, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    item.Source.Dispose();
                    context.Pending.Completed();
                }
            }
        }
    }

    private static async Task ProcessOneAsync(
        ScanWorkItem item,
        DeepScanContext context,
        IReadOnlyList<IPipelineStage> stages,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            item.Disposition = WorkItemDisposition.Cancelled;
            return;
        }

        ScanLease lease;
        try { lease = await context.Throttle.AcquireAsync(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { item.Disposition = WorkItemDisposition.Cancelled; return; }

        using (lease)
        {
            context.Telemetry.IncActiveWorkers();
            context.Telemetry.SetCurrentTarget(item.Source.LogicalPath);
            try
            {
                foreach (var stage in stages)
                {
                    if (cancellationToken.IsCancellationRequested) { item.Disposition = WorkItemDisposition.Cancelled; return; }
                    if (item.Disposition is WorkItemDisposition.Skipped or WorkItemDisposition.Failed or WorkItemDisposition.Cancelled)
                        return;

                    if (context.Profile.EmitStageTelemetry) context.Telemetry.SetStage(stage.Name);
                    StageResult result;
                    try
                    {
                        result = await stage.ExecuteAsync(item, context, cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        item.Disposition = WorkItemDisposition.Cancelled;
                        return;
                    }
                    catch (Exception ex)
                    {
                        context.Telemetry.IncError();
                        context.Logger.ModuleFailure(stage.Name, item.Source.LogicalPath, ex);
                        item.Disposition = WorkItemDisposition.Failed;
                        item.DispositionReason = $"stage {stage.Name} threw";
                        return;
                    }
                    if (result == StageResult.Skip) return;
                }
            }
            finally
            {
                context.Telemetry.DecActiveWorkers();
            }
        }

        try { await context.Throttle.YieldIfThrottledAsync(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { /* worker tearing down */ }
    }

    /// <summary>
    /// Builds the canonical stage list for a deep scan. Future modules plug in
    /// by inserting themselves at the appropriate spot in this list.
    /// </summary>
    public static IReadOnlyList<IPipelineStage> BuildDefaultStages(
        ISignatureService signatures,
        DetectionPipeline detectionPipeline)
    {
        return new IPipelineStage[]
        {
            new NormalizationStage(),
            new PreFilterStage(),
            new FileTypeIdentificationStage(),
            new HashingStage(),
            new ReputationStage(signatures),
            new DetectionStage(detectionPipeline),
            new ArchiveExpansionStage(),
            new AlternateDataStreamStage(),
            new CorrelationStage(),
            new ClassificationStage(),
            new ReportingStage(),
        };
    }
}

public sealed class DeepScanOrchestratorOptions
{
    public required DeepScanProfileSettings Profile { get; init; }
    public required DiscoveryStage Discovery { get; init; }
    public required IReadOnlyList<IPipelineStage> Stages { get; init; }
    public required DetectionModuleRegistry Modules { get; init; }
    public required IScanLogger Logger { get; init; }
    public DeepScanTelemetry? Telemetry { get; init; }
}

public sealed class DeepScanResult
{
    public ScanWorkItem[] Items { get; init; } = Array.Empty<ScanWorkItem>();
    public required DeepScanTelemetrySnapshot Telemetry { get; init; }
    public bool Cancelled { get; init; }
    public bool TimedOut { get; init; }
}
