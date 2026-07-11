using System;
using System.Collections.Generic;
using System.Threading;

namespace DataVanger.Memory.Rules;

/// <summary>
/// Detects RX private memory with no backing file — i.e. anonymous
/// executable code that did not arrive via the standard image loader.
/// Strong injection / manual-mapping primitive but, again, legitimate
/// .NET ReadyToRun / JIT can occasionally produce similar regions.
/// </summary>
public sealed class AnonymousExecutableRule : IMemoryRule
{
    public string RuleId => "Memory.AnonExec";
    public string Title => "Anonymous executable private region";
    public bool RequiresBytes => false;

    public IReadOnlyList<MemoryFinding> Evaluate(
        ProcessSnapshot process,
        MemoryRegion region,
        byte[] sampleBytes,
        CancellationToken cancellationToken)
    {
        if (region is null) return Array.Empty<MemoryFinding>();
        if (region.Kind != MemoryRegionKind.Private) return Array.Empty<MemoryFinding>();
        if (!region.Protection.IsExecutable()) return Array.Empty<MemoryFinding>();
        if (region.Protection.IsWritable()) return Array.Empty<MemoryFinding>(); // RWX handled separately
        if (!string.IsNullOrWhiteSpace(region.BackingPath)) return Array.Empty<MemoryFinding>();

        return new[]
        {
            new MemoryFinding(
                kind: MemoryFindingKind.AnonymousExecutableRegion,
                processId: process?.ProcessId ?? 0,
                processName: process?.ProcessName ?? "",
                regionBase: region.BaseAddress,
                regionSize: region.Size,
                protection: region.Protection,
                regionKind: region.Kind,
                severity: MemoryScanSeverity.Medium,
                description: $"Região RX anônima em 0x{region.BaseAddress:X} sem imagem de origem — " +
                             "indicador heurístico de carregamento manual.",
                scoreDelta: 3),
        };
    }
}
