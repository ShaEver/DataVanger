using System.Collections.Generic;
using System.Threading;

namespace DataVanger.Memory.Readers;

/// <summary>
/// Abstraction over the platform-specific bits of memory inspection.
/// All operations are best-effort and never throw on access denied /
/// disappearing processes — they return empty results instead.
/// </summary>
public interface IMemoryReader
{
    /// <summary>True if this reader can actually read memory on the current host.</summary>
    bool IsSupported { get; }

    /// <summary>Enumerate processes visible to this reader.</summary>
    IEnumerable<ProcessSnapshot> EnumerateProcesses(CancellationToken cancellationToken);

    /// <summary>Enumerate the memory regions for a process. Empty when access denied.</summary>
    IEnumerable<MemoryRegion> EnumerateRegions(ProcessSnapshot process, CancellationToken cancellationToken);

    /// <summary>
    /// Read up to <paramref name="maxBytes"/> bytes from the start of the region. Returns
    /// an empty array (never null, never throws) when the read fails for any reason.
    /// </summary>
    byte[] ReadBytes(MemoryRegion region, int maxBytes, CancellationToken cancellationToken);
}
