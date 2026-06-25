using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using DataVanger.Core.Abstractions;
using DataVanger.Engine.DeepScan;

namespace DataVanger.Engine.DeepScan.Stages;

/// <summary>
/// Walks the supplied root directories using the resilient filesystem service
/// and pushes <see cref="ScanWorkItem"/> instances into the orchestrator's
/// bounded channel.
///
/// Unlike the other stages, discovery is invoked ONCE by the orchestrator
/// (not per work item). Keeping it behind the same interface lets us swap in
/// alternative sources later — e.g. an enumerator that reads from a quarantine
/// folder or from realtime monitor events — without changing the orchestrator.
/// </summary>
public sealed class DiscoveryStage
{
    private readonly IFileSystemService _fileSystem;

    public DiscoveryStage(IFileSystemService fileSystem)
    {
        _fileSystem = fileSystem;
    }

    public string Name => "Discovery";

    public async Task DiscoverAsync(
        IEnumerable<string> roots,
        ChannelWriter<ScanWorkItem> writer,
        DeepScanContext context,
        CancellationToken cancellationToken)
    {
        context.Telemetry.SetStage(Name);
        foreach (var root in roots)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (context.OverallTimeoutElapsed()) break;

            foreach (var file in _fileSystem.EnumerateFiles(root, cancellationToken,
                         onAccessDenied: path => context.Logger.SkippedFile(path, "access denied")))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (context.OverallTimeoutElapsed()) break;

                ScanWorkItem item;
                try
                {
                    item = new ScanWorkItem(new FileContentSource(file), depth: 0);
                }
                catch
                {
                    context.Telemetry.IncError();
                    continue;
                }

                context.Telemetry.IncDiscovered();
                context.Pending.Enqueued();
                bool written = false;
                try
                {
                    if (await writer.WaitToWriteAsync(cancellationToken).ConfigureAwait(false))
                    {
                        written = writer.TryWrite(item);
                        if (written) context.Telemetry.IncQueueDepth();
                    }
                }
                finally
                {
                    if (!written) context.Pending.Completed();
                }
            }
        }
    }
}
