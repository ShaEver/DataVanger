using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Shared, mostly-immutable runtime state for one deep scan invocation.
///
/// Items the orchestrator and stages need across workers — settings, throttle,
/// channel writer for archive expansion, telemetry, recursion budgets — are
/// exposed here as read-only properties. Mutable fields are confined to
/// thread-safe counters in <see cref="DeepScanTelemetry"/> and the throttle
/// semaphore in <see cref="Throttle"/>.
/// </summary>
public sealed class DeepScanContext
{
    public DeepScanContext(
        DeepScanProfileSettings profile,
        ScanContext scanContext,
        DeepScanTelemetry telemetry,
        ScanThrottle throttle,
        ChannelWriter<ScanWorkItem> queueWriter,
        DetectionModuleRegistry modules,
        IScanLogger logger,
        PendingWorkCounter pending)
    {
        Profile = profile ?? throw new ArgumentNullException(nameof(profile));
        ScanContext = scanContext ?? throw new ArgumentNullException(nameof(scanContext));
        Telemetry = telemetry ?? throw new ArgumentNullException(nameof(telemetry));
        Throttle = throttle ?? throw new ArgumentNullException(nameof(throttle));
        QueueWriter = queueWriter ?? throw new ArgumentNullException(nameof(queueWriter));
        Modules = modules ?? throw new ArgumentNullException(nameof(modules));
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        Pending = pending ?? throw new ArgumentNullException(nameof(pending));
        OverallTimeoutAt = profile.OverallTimeout > TimeSpan.Zero
            ? DateTime.UtcNow.Add(profile.OverallTimeout)
            : DateTime.MaxValue;
    }

    public DeepScanProfileSettings Profile { get; }
    public ScanContext ScanContext { get; }
    public DeepScanTelemetry Telemetry { get; }
    public ScanThrottle Throttle { get; }
    public ChannelWriter<ScanWorkItem> QueueWriter { get; }
    public DetectionModuleRegistry Modules { get; }
    public IScanLogger Logger { get; }

    /// <summary>
    /// Tracks how many work items the channel must still drain. Discovery and
    /// archive expansion call <see cref="PendingWorkCounter.Enqueued"/> for each
    /// item produced; workers call <see cref="PendingWorkCounter.Completed"/>
    /// when they finish one. The orchestrator closes the channel once the
    /// counter reaches zero AND discovery has signalled completion.
    /// </summary>
    public PendingWorkCounter Pending { get; }

    public DateTime OverallTimeoutAt { get; }

    /// <summary>Findings accumulated by the reporting stage. Thread-safe append-only list.</summary>
    public List<ScanWorkItem> Findings { get; } = new();
    private readonly object _findingsLock = new();
    private long _findingsDropped;

    /// <summary>Count of findings discarded because <see cref="DeepScanProfileSettings.MaxFindings"/> was reached.</summary>
    public long FindingsDroppedCount => System.Threading.Interlocked.Read(ref _findingsDropped);

    public void AddFinding(ScanWorkItem item)
    {
        if (item is null) return;
        lock (_findingsLock)
        {
            int cap = Profile.MaxFindings;
            if (cap > 0 && Findings.Count >= cap)
            {
                System.Threading.Interlocked.Increment(ref _findingsDropped);
                return;
            }
            Findings.Add(item);
        }
    }

    /// <summary>True when the configured overall scan budget has been exhausted.</summary>
    public bool OverallTimeoutElapsed() => DateTime.UtcNow >= OverallTimeoutAt;
}
