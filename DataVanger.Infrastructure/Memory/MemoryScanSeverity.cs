namespace DataVanger.Memory;

/// <summary>
/// Severity band for a memory finding. Intentionally does NOT include a
/// "Confirmed" tier — memory heuristics alone must never confirm malware.
/// </summary>
public enum MemoryScanSeverity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}
