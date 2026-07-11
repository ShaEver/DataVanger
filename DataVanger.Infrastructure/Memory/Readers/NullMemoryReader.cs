using System;
using System.Collections.Generic;
using System.Threading;

namespace DataVanger.Memory.Readers;

/// <summary>
/// Read-nothing fallback reader. Used when the host does not support
/// process memory inspection or when the scanner is configured to run
/// in a degraded environment (no admin, sandbox, CI, etc.). Calling
/// into it is always safe.
/// </summary>
public sealed class NullMemoryReader : IMemoryReader
{
    public static readonly NullMemoryReader Instance = new();

    public bool IsSupported => false;

    public IEnumerable<ProcessSnapshot> EnumerateProcesses(CancellationToken cancellationToken)
        => Array.Empty<ProcessSnapshot>();

    public IEnumerable<MemoryRegion> EnumerateRegions(ProcessSnapshot process, CancellationToken cancellationToken)
        => Array.Empty<MemoryRegion>();

    public byte[] ReadBytes(MemoryRegion region, int maxBytes, CancellationToken cancellationToken)
        => Array.Empty<byte>();
}
