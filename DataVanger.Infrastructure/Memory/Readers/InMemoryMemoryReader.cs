using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace DataVanger.Memory.Readers;

/// <summary>
/// Deterministic in-memory reader used by tests and by hosts that want
/// to drive the memory pipeline with pre-baked snapshots (e.g. when ETW
/// telemetry already gave us synthetic regions). Holds everything in
/// dictionaries; never touches the OS.
/// </summary>
public sealed class InMemoryMemoryReader : IMemoryReader
{
    private readonly Dictionary<int, ProcessSnapshot> _processes = new();
    private readonly Dictionary<int, List<MemoryRegion>> _regions = new();
    private readonly Dictionary<(int Pid, ulong Base), byte[]> _bytes = new();

    public bool IsSupported => true;

    public InMemoryMemoryReader AddProcess(ProcessSnapshot snapshot)
    {
        if (snapshot is null) throw new ArgumentNullException(nameof(snapshot));
        _processes[snapshot.ProcessId] = snapshot;
        if (!_regions.ContainsKey(snapshot.ProcessId))
            _regions[snapshot.ProcessId] = new List<MemoryRegion>();
        return this;
    }

    public InMemoryMemoryReader AddRegion(MemoryRegion region, byte[]? backingBytes = null)
    {
        if (region is null) throw new ArgumentNullException(nameof(region));
        if (!_regions.TryGetValue(region.ProcessId, out var list))
        {
            list = new List<MemoryRegion>();
            _regions[region.ProcessId] = list;
        }
        list.Add(region);
        if (backingBytes is not null)
            _bytes[(region.ProcessId, region.BaseAddress)] = backingBytes;
        return this;
    }

    /// <summary>Simulate process disappearance between enumeration and region walk.</summary>
    public void RemoveProcess(int processId)
    {
        _processes.Remove(processId);
        _regions.Remove(processId);
    }

    public IEnumerable<ProcessSnapshot> EnumerateProcesses(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return _processes.Values.ToArray();
    }

    public IEnumerable<MemoryRegion> EnumerateRegions(ProcessSnapshot process, CancellationToken cancellationToken)
    {
        if (process is null) return Array.Empty<MemoryRegion>();
        if (!process.IsAccessible) return Array.Empty<MemoryRegion>();
        if (!_regions.TryGetValue(process.ProcessId, out var list))
            return Array.Empty<MemoryRegion>();
        cancellationToken.ThrowIfCancellationRequested();
        return list.ToArray();
    }

    public byte[] ReadBytes(MemoryRegion region, int maxBytes, CancellationToken cancellationToken)
    {
        if (region is null || maxBytes <= 0) return Array.Empty<byte>();
        cancellationToken.ThrowIfCancellationRequested();
        if (!_bytes.TryGetValue((region.ProcessId, region.BaseAddress), out var buf) || buf is null)
            return Array.Empty<byte>();
        int take = Math.Min(maxBytes, buf.Length);
        if (take == buf.Length) return buf;
        var slice = new byte[take];
        Buffer.BlockCopy(buf, 0, slice, 0, take);
        return slice;
    }
}
