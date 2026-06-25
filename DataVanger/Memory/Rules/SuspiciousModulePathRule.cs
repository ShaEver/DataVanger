using System;
using System.Collections.Generic;
using System.Threading;

namespace DataVanger.Memory.Rules;

/// <summary>
/// Looks at MEM_IMAGE regions whose backing path lives in a high-risk
/// folder (Temp, AppData\Roaming, etc.) and whose hosting process is
/// not trusted-signed. This catches "loaded a DLL from %TEMP%" style
/// sideloading without confirming anything.
/// </summary>
public sealed class SuspiciousModulePathRule : IMemoryRule
{
    private static readonly string[] SuspiciousFragments =
    {
        @"\appdata\local\temp\",
        @"\appdata\roaming\",
        @"\users\public\",
        @"\windows\temp\",
        @"\programdata\",
    };

    public string RuleId => "Memory.SuspiciousModulePath";
    public string Title => "Loaded module from suspicious path";
    public bool RequiresBytes => false;

    public IReadOnlyList<MemoryFinding> Evaluate(
        ProcessSnapshot process,
        MemoryRegion region,
        byte[] sampleBytes,
        CancellationToken cancellationToken)
    {
        if (region is null) return Array.Empty<MemoryFinding>();
        if (region.Kind != MemoryRegionKind.Image) return Array.Empty<MemoryFinding>();
        if (string.IsNullOrWhiteSpace(region.BackingPath)) return Array.Empty<MemoryFinding>();
        if (process is { IsSigned: true }) return Array.Empty<MemoryFinding>();

        string lower = region.BackingPath.ToLowerInvariant();
        bool hit = false;
        foreach (var frag in SuspiciousFragments)
        {
            if (lower.Contains(frag)) { hit = true; break; }
        }
        if (!hit) return Array.Empty<MemoryFinding>();

        return new[]
        {
            new MemoryFinding(
                kind: MemoryFindingKind.SuspiciousModulePath,
                processId: process?.ProcessId ?? 0,
                processName: process?.ProcessName ?? "",
                regionBase: region.BaseAddress,
                regionSize: region.Size,
                protection: region.Protection,
                regionKind: region.Kind,
                severity: MemoryScanSeverity.Medium,
                description: $"Módulo carregado de caminho não-confiável: {region.BackingPath}. Heurístico.",
                scoreDelta: 2,
                backingPath: region.BackingPath),
        };
    }
}
