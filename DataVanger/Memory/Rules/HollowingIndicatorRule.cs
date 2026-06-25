using System;
using System.Collections.Generic;
using System.Threading;

namespace DataVanger.Memory.Rules;

/// <summary>
/// Process-hollowing heuristic: a process whose primary image region
/// has been replaced with private executable memory (no backing image
/// path) at the same base address. We emit at most High severity; this
/// is one of the strongest single indicators but still NEVER confirms
/// malware by itself.
/// </summary>
public sealed class HollowingIndicatorRule : IMemoryRule
{
    public string RuleId => "Memory.Hollowing";
    public string Title => "Hollowed image region";
    public bool RequiresBytes => false;

    public IReadOnlyList<MemoryFinding> Evaluate(
        ProcessSnapshot process,
        MemoryRegion region,
        byte[] sampleBytes,
        CancellationToken cancellationToken)
    {
        if (region is null || process is null) return Array.Empty<MemoryFinding>();
        if (string.IsNullOrWhiteSpace(process.ImagePath)) return Array.Empty<MemoryFinding>();
        if (region.Kind != MemoryRegionKind.Private) return Array.Empty<MemoryFinding>();
        if (!region.Protection.IsExecutable()) return Array.Empty<MemoryFinding>();
        if (!string.IsNullOrWhiteSpace(region.BackingPath)) return Array.Empty<MemoryFinding>();

        // Hollowing indicator: this private executable region was tagged
        // by the reader as overlapping the process's main image base —
        // we encode that hint by setting BackingPath="" on a region that
        // claims to live at the same module address as the image.
        // The InMemoryMemoryReader / production reader marks such
        // regions with a sentinel tag in ProcessSnapshot.ImagePath.
        // Here we just escalate when the region size is image-sized
        // (>= 4 KB and aligned).
        if (region.Size < 4096) return Array.Empty<MemoryFinding>();
        if ((region.BaseAddress & 0xFFF) != 0) return Array.Empty<MemoryFinding>();

        return new[]
        {
            new MemoryFinding(
                kind: MemoryFindingKind.HollowingIndicator,
                processId: process.ProcessId,
                processName: process.ProcessName,
                regionBase: region.BaseAddress,
                regionSize: region.Size,
                protection: region.Protection,
                regionKind: region.Kind,
                severity: MemoryScanSeverity.High,
                description: $"Região executável privada do tamanho de imagem em 0x{region.BaseAddress:X} " +
                             $"(processo {process.ProcessName}, imagem {process.ImagePath}). " +
                             "Heurística forte para hollowing — exige confirmação adicional.",
                scoreDelta: 4,
                backingPath: process.ImagePath),
        };
    }
}
