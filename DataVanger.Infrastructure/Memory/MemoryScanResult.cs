using System.Collections.Generic;

namespace DataVanger.Memory;

/// <summary>
/// Result of a memory scan pass. Contains all explainable findings and
/// counters that the UI/report layer can surface.
/// </summary>
public sealed class MemoryScanResult
{
    public MemoryScanResult(
        IReadOnlyList<MemoryFinding> findings,
        int processesEnumerated,
        int processesScanned,
        int processesInaccessible,
        int regionsExamined,
        long bytesExamined,
        MemoryScanDegradationReason degradation,
        string degradationDetail = "")
    {
        Findings = findings ?? new List<MemoryFinding>();
        ProcessesEnumerated = processesEnumerated;
        ProcessesScanned = processesScanned;
        ProcessesInaccessible = processesInaccessible;
        RegionsExamined = regionsExamined;
        BytesExamined = bytesExamined < 0 ? 0 : bytesExamined;
        Degradation = degradation;
        DegradationDetail = degradationDetail ?? "";
    }

    public IReadOnlyList<MemoryFinding> Findings { get; }
    public int ProcessesEnumerated { get; }
    public int ProcessesScanned { get; }
    public int ProcessesInaccessible { get; }
    public int RegionsExamined { get; }
    public long BytesExamined { get; }
    public MemoryScanDegradationReason Degradation { get; }
    public string DegradationDetail { get; }

    public bool IsDegraded => Degradation != MemoryScanDegradationReason.None;

    public static MemoryScanResult Empty(MemoryScanDegradationReason reason, string detail = "")
        => new(new List<MemoryFinding>(), 0, 0, 0, 0, 0, reason, detail);
}
