using System;

namespace DataVanger.Memory;

/// <summary>
/// Read-only description of a single memory region inside a process.
///
/// Constructed by an <see cref="IMemoryReader"/>; consumed by memory
/// rules and the analyzer. Does not own the region's bytes — they are
/// fetched on demand via the reader so we never hold whole-process
/// snapshots in memory.
/// </summary>
public sealed class MemoryRegion
{
    public MemoryRegion(
        int processId,
        ulong baseAddress,
        long size,
        MemoryProtection protection,
        MemoryRegionKind kind,
        string? backingPath = null)
    {
        ProcessId = processId;
        BaseAddress = baseAddress;
        Size = size < 0 ? 0 : size;
        Protection = protection;
        Kind = kind;
        BackingPath = backingPath ?? "";
    }

    public int ProcessId { get; }
    public ulong BaseAddress { get; }
    public long Size { get; }
    public MemoryProtection Protection { get; }
    public MemoryRegionKind Kind { get; }

    /// <summary>
    /// File path backing this region for Image/Mapped kinds. Empty for
    /// private anonymous memory.
    /// </summary>
    public string BackingPath { get; }

    public bool IsAnonymous => Kind == MemoryRegionKind.Private && string.IsNullOrWhiteSpace(BackingPath);

    public override string ToString()
        => $"PID={ProcessId} @0x{BaseAddress:X} size={Size} prot={Protection.Describe()} kind={Kind}";
}
