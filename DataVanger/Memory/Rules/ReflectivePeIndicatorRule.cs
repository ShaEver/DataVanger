using System;
using System.Collections.Generic;
using System.Threading;

namespace DataVanger.Memory.Rules;

/// <summary>
/// Looks for an MZ / PE\0\0 structure inside private executable memory.
/// A loader-registered DLL would show up as MEM_IMAGE with BackingPath
/// set — finding the same magic in MEM_PRIVATE is a strong reflective
/// DLL / manual-map indicator.
/// </summary>
public sealed class ReflectivePeIndicatorRule : IMemoryRule
{
    public string RuleId => "Memory.ReflectivePE";
    public string Title => "Reflective PE in private memory";
    public bool RequiresBytes => true;

    public IReadOnlyList<MemoryFinding> Evaluate(
        ProcessSnapshot process,
        MemoryRegion region,
        byte[] sampleBytes,
        CancellationToken cancellationToken)
    {
        if (region is null) return Array.Empty<MemoryFinding>();
        if (region.Kind != MemoryRegionKind.Private) return Array.Empty<MemoryFinding>();
        if (!region.Protection.IsExecutable()) return Array.Empty<MemoryFinding>();
        if (!string.IsNullOrWhiteSpace(region.BackingPath)) return Array.Empty<MemoryFinding>();
        if (sampleBytes is null || sampleBytes.Length < 0x40) return Array.Empty<MemoryFinding>();

        if (sampleBytes[0] != (byte)'M' || sampleBytes[1] != (byte)'Z') return Array.Empty<MemoryFinding>();

        // Try to follow e_lfanew like a real PE header walker would.
        int e_lfanew = BitConverter.ToInt32(sampleBytes, 0x3C);
        if (e_lfanew < 0 || e_lfanew + 4 > sampleBytes.Length) return Array.Empty<MemoryFinding>();
        if (sampleBytes[e_lfanew] != (byte)'P' || sampleBytes[e_lfanew + 1] != (byte)'E'
            || sampleBytes[e_lfanew + 2] != 0 || sampleBytes[e_lfanew + 3] != 0)
            return Array.Empty<MemoryFinding>();

        return new[]
        {
            new MemoryFinding(
                kind: MemoryFindingKind.ReflectivePeIndicator,
                processId: process?.ProcessId ?? 0,
                processName: process?.ProcessName ?? "",
                regionBase: region.BaseAddress,
                regionSize: region.Size,
                protection: region.Protection,
                regionKind: region.Kind,
                severity: MemoryScanSeverity.High,
                description: $"Estrutura PE encontrada em memória privada executável (0x{region.BaseAddress:X}). " +
                             "Heurística forte de reflective-DLL — confirmação ainda exige evidência adicional.",
                scoreDelta: 5),
        };
    }
}
