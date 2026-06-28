using System;

namespace DataVanger.Memory;

/// <summary>
/// A single explainable memory observation. Memory findings are the
/// scanner's unit of evidence — they describe what was seen, where, and
/// at what severity. Anti-FP invariant: <see cref="CanConfirmMalware"/>
/// is always false. Conversion to <see cref="DataVanger.Core.Evidence"/>
/// happens via <see cref="MemoryEvidenceFactory"/>, which preserves that
/// invariant.
/// </summary>
public sealed class MemoryFinding
{
    public MemoryFinding(
        MemoryFindingKind kind,
        int processId,
        string processName,
        ulong regionBase,
        long regionSize,
        MemoryProtection protection,
        MemoryRegionKind regionKind,
        MemoryScanSeverity severity,
        string description,
        int scoreDelta,
        DateTime? timestampUtc = null,
        string backingPath = "")
    {
        Kind = kind;
        ProcessId = processId;
        ProcessName = processName ?? "";
        RegionBase = regionBase;
        RegionSize = regionSize < 0 ? 0 : regionSize;
        Protection = protection;
        RegionKind = regionKind;
        Severity = severity;
        Description = description ?? "";
        ScoreDelta = scoreDelta;
        TimestampUtc = (timestampUtc ?? DateTime.UtcNow).ToUniversalTime();
        BackingPath = backingPath ?? "";
    }

    public MemoryFindingKind Kind { get; }
    public int ProcessId { get; }
    public string ProcessName { get; }
    public ulong RegionBase { get; }
    public long RegionSize { get; }
    public MemoryProtection Protection { get; }
    public MemoryRegionKind RegionKind { get; }
    public MemoryScanSeverity Severity { get; }
    public string Description { get; }
    public int ScoreDelta { get; }
    public DateTime TimestampUtc { get; }
    public string BackingPath { get; }

    /// <summary>Anti-FP contract: never true.</summary>
    public bool CanConfirmMalware => false;

    public override string ToString()
        => $"[Memory.{Kind} {Severity}] pid={ProcessId} {ProcessName} @0x{RegionBase:X}: {Description}";
}
