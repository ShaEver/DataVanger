using System;
using System.Collections.Generic;
using System.Threading;
using DataVanger.Core;
using DataVanger.Core.Domain;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Mutable per-target state that flows through every stage of the deep scan
/// pipeline. Created at discovery time, finalised at reporting time.
///
/// A work item is processed by ONE worker at a time, so per-item state is
/// not synchronised. Anything shared across items lives in
/// <see cref="DeepScanContext"/>.
/// </summary>
public sealed class ScanWorkItem
{
    public ScanWorkItem(ContentSource source, int depth, ScanWorkItem? parent = null)
    {
        Source = source ?? throw new ArgumentNullException(nameof(source));
        Depth = depth;
        Parent = parent;
        Id = Interlocked.Increment(ref s_id);
        CreatedAt = DateTime.UtcNow;
        // Defer ScanTarget allocation until we have a real FileInfo; for
        // in-memory sources the value is filled by stages when needed.
        if (source is FileContentSource f) Target = new ScanTarget(f.File);
    }

    private static long s_id;

    public long Id { get; }
    public DateTime CreatedAt { get; }

    public ContentSource Source { get; }
    public int Depth { get; }
    public ScanWorkItem? Parent { get; }

    public ScanTarget? Target { get; set; }

    public SniffedFileType SniffedType { get; set; } = SniffedFileType.Unknown;
    public string? Sha256 { get; set; }
    public bool KnownSafe { get; set; }
    public bool KnownMalicious { get; set; }

    public List<Evidence> Evidence { get; } = new();
    public int Score { get; set; }

    public WorkItemDisposition Disposition { get; set; } = WorkItemDisposition.Pending;
    public string? DispositionReason { get; set; }

    /// <summary>
    /// Logical traversal path: file:/path -> archive:entry -> archive:nested-entry.
    /// Useful in reports so a finding inside a nested archive can be located.
    /// </summary>
    public string TraversalPath()
    {
        if (Parent is null) return Source.LogicalPath;
        return Parent.TraversalPath() + " -> " + Source.LogicalPath;
    }

    public void AddEvidence(Evidence evidence)
    {
        if (evidence is null) return;
        Evidence.Add(evidence);
        Score += evidence.ScoreDelta;
    }
}

public enum WorkItemDisposition
{
    Pending,
    Completed,
    Skipped,
    Failed,
    TimedOut,
    Cancelled,
}
