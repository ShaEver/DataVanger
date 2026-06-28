using System;
using System.Collections.Generic;
using System.Threading;

namespace DataVanger.Memory.Rules;

/// <summary>
/// Detects PAGE_EXECUTE_READWRITE in private memory.
///
/// RWX in private memory is the classic shellcode primitive (alloc RWX,
/// write, jump). It is also legitimately used by JIT engines and some
/// anti-cheat systems, so the rule emits Medium severity at most — the
/// caller's correlation engine must escalate based on other evidence.
/// </summary>
public sealed class RwxRegionRule : IMemoryRule
{
    public string RuleId => "Memory.RwxPrivate";
    public string Title => "RWX private memory";
    public bool RequiresBytes => false;

    public IReadOnlyList<MemoryFinding> Evaluate(
        ProcessSnapshot process,
        MemoryRegion region,
        byte[] sampleBytes,
        CancellationToken cancellationToken)
    {
        if (region is null) return Array.Empty<MemoryFinding>();
        if (region.Kind != MemoryRegionKind.Private) return Array.Empty<MemoryFinding>();
        if (!region.Protection.IsRwx()) return Array.Empty<MemoryFinding>();

        return new[]
        {
            new MemoryFinding(
                kind: MemoryFindingKind.RwxPrivateRegion,
                processId: process?.ProcessId ?? 0,
                processName: process?.ProcessName ?? "",
                regionBase: region.BaseAddress,
                regionSize: region.Size,
                protection: region.Protection,
                regionKind: region.Kind,
                severity: MemoryScanSeverity.Medium,
                description: $"Região privada RWX em 0x{region.BaseAddress:X} ({region.Size} bytes). " +
                             "Indicador heurístico — pode ser JIT/anti-cheat legítimo.",
                scoreDelta: 3),
        };
    }
}
