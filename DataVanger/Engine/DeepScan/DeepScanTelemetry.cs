using System;
using System.Threading;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Thread-safe counters and observable signals for the deep scan pipeline.
/// Every stage emits into here; the orchestrator surfaces a snapshot to the
/// UI / reports without holding any locks.
/// </summary>
public sealed class DeepScanTelemetry
{
    public string Stage { get; private set; } = "";
    public string CurrentTarget { get; private set; } = "";

    private long _discovered;
    private long _normalized;
    private long _preFiltered;
    private long _typeIdentified;
    private long _hashed;
    private long _reputationLookups;
    private long _detectionRuns;
    private long _archiveExpansions;
    private long _archiveEntriesInspected;
    private long _findings;
    private long _skipped;
    private long _errors;
    private long _timeouts;
    private long _recursionAborts;
    private long _zipBombAborts;
    private long _queueDepth;
    private long _maxQueueDepth;
    private long _activeWorkers;
    private long _maxActiveWorkers;
    private long _maxRecursionDepth;

    public long Discovered => Interlocked.Read(ref _discovered);
    public long Normalized => Interlocked.Read(ref _normalized);
    public long PreFiltered => Interlocked.Read(ref _preFiltered);
    public long TypeIdentified => Interlocked.Read(ref _typeIdentified);
    public long Hashed => Interlocked.Read(ref _hashed);
    public long ReputationLookups => Interlocked.Read(ref _reputationLookups);
    public long DetectionRuns => Interlocked.Read(ref _detectionRuns);
    public long ArchiveExpansions => Interlocked.Read(ref _archiveExpansions);
    public long ArchiveEntriesInspected => Interlocked.Read(ref _archiveEntriesInspected);
    public long Findings => Interlocked.Read(ref _findings);
    public long Skipped => Interlocked.Read(ref _skipped);
    public long Errors => Interlocked.Read(ref _errors);
    public long Timeouts => Interlocked.Read(ref _timeouts);
    public long RecursionAborts => Interlocked.Read(ref _recursionAborts);
    public long ZipBombAborts => Interlocked.Read(ref _zipBombAborts);
    public long QueueDepth => Interlocked.Read(ref _queueDepth);
    public long MaxQueueDepth => Interlocked.Read(ref _maxQueueDepth);
    public long ActiveWorkers => Interlocked.Read(ref _activeWorkers);
    public long MaxActiveWorkers => Interlocked.Read(ref _maxActiveWorkers);
    public long MaxRecursionDepth => Interlocked.Read(ref _maxRecursionDepth);

    internal void SetStage(string stage) => Stage = stage ?? "";
    internal void SetCurrentTarget(string target) => CurrentTarget = target ?? "";

    internal void IncDiscovered() => Interlocked.Increment(ref _discovered);
    internal void IncNormalized() => Interlocked.Increment(ref _normalized);
    internal void IncPreFiltered() => Interlocked.Increment(ref _preFiltered);
    internal void IncTypeIdentified() => Interlocked.Increment(ref _typeIdentified);
    internal void IncHashed() => Interlocked.Increment(ref _hashed);
    internal void IncReputation() => Interlocked.Increment(ref _reputationLookups);
    internal void IncDetection() => Interlocked.Increment(ref _detectionRuns);
    internal void IncArchiveExpansion() => Interlocked.Increment(ref _archiveExpansions);
    internal void AddArchiveEntries(long n) { if (n > 0) Interlocked.Add(ref _archiveEntriesInspected, n); }
    internal void IncFinding() => Interlocked.Increment(ref _findings);
    internal void IncSkipped() => Interlocked.Increment(ref _skipped);
    internal void IncError() => Interlocked.Increment(ref _errors);
    internal void IncTimeout() => Interlocked.Increment(ref _timeouts);
    internal void IncRecursionAbort() => Interlocked.Increment(ref _recursionAborts);
    internal void IncZipBombAbort() => Interlocked.Increment(ref _zipBombAborts);

    internal void IncQueueDepth()
    {
        long depth = Interlocked.Increment(ref _queueDepth);
        BumpMax(ref _maxQueueDepth, depth);
    }
    internal void DecQueueDepth() => Interlocked.Decrement(ref _queueDepth);

    internal void IncActiveWorkers()
    {
        long active = Interlocked.Increment(ref _activeWorkers);
        BumpMax(ref _maxActiveWorkers, active);
    }
    internal void DecActiveWorkers() => Interlocked.Decrement(ref _activeWorkers);

    internal void NoteRecursionDepth(int depth) => BumpMax(ref _maxRecursionDepth, depth);

    private static void BumpMax(ref long target, long candidate)
    {
        long current;
        do
        {
            current = Interlocked.Read(ref target);
            if (candidate <= current) return;
        }
        while (Interlocked.CompareExchange(ref target, candidate, current) != current);
    }

    public DeepScanTelemetrySnapshot Snapshot() => new()
    {
        Stage = Stage,
        CurrentTarget = CurrentTarget,
        Discovered = Discovered,
        Normalized = Normalized,
        PreFiltered = PreFiltered,
        TypeIdentified = TypeIdentified,
        Hashed = Hashed,
        ReputationLookups = ReputationLookups,
        DetectionRuns = DetectionRuns,
        ArchiveExpansions = ArchiveExpansions,
        ArchiveEntriesInspected = ArchiveEntriesInspected,
        Findings = Findings,
        Skipped = Skipped,
        Errors = Errors,
        Timeouts = Timeouts,
        RecursionAborts = RecursionAborts,
        ZipBombAborts = ZipBombAborts,
        QueueDepth = QueueDepth,
        MaxQueueDepth = MaxQueueDepth,
        ActiveWorkers = ActiveWorkers,
        MaxActiveWorkers = MaxActiveWorkers,
        MaxRecursionDepth = MaxRecursionDepth,
    };
}

public sealed class DeepScanTelemetrySnapshot
{
    public string Stage { get; init; } = "";
    public string CurrentTarget { get; init; } = "";
    public long Discovered { get; init; }
    public long Normalized { get; init; }
    public long PreFiltered { get; init; }
    public long TypeIdentified { get; init; }
    public long Hashed { get; init; }
    public long ReputationLookups { get; init; }
    public long DetectionRuns { get; init; }
    public long ArchiveExpansions { get; init; }
    public long ArchiveEntriesInspected { get; init; }
    public long Findings { get; init; }
    public long Skipped { get; init; }
    public long Errors { get; init; }
    public long Timeouts { get; init; }
    public long RecursionAborts { get; init; }
    public long ZipBombAborts { get; init; }
    public long QueueDepth { get; init; }
    public long MaxQueueDepth { get; init; }
    public long ActiveWorkers { get; init; }
    public long MaxActiveWorkers { get; init; }
    public long MaxRecursionDepth { get; init; }
}
