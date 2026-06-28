using System;
using System.Collections.Generic;
using System.Threading;

namespace DataVanger.Memory.Rules;

/// <summary>
/// Flags executable memory whose contents look like packed/encrypted
/// payload (Shannon entropy &gt;= configured threshold). Very weak on its
/// own — emits Low severity so the correlation engine has to combine it
/// with other indicators before it counts.
/// </summary>
public sealed class HighEntropyExecutableRule : IMemoryRule
{
    private readonly double _threshold;

    public HighEntropyExecutableRule(double threshold = 7.5)
    {
        if (threshold < 0) threshold = 0;
        if (threshold > 8) threshold = 8;
        _threshold = threshold;
    }

    public string RuleId => "Memory.HighEntropyExec";
    public string Title => "High entropy in executable region";
    public bool RequiresBytes => true;

    public IReadOnlyList<MemoryFinding> Evaluate(
        ProcessSnapshot process,
        MemoryRegion region,
        byte[] sampleBytes,
        CancellationToken cancellationToken)
    {
        if (region is null) return Array.Empty<MemoryFinding>();
        if (!region.Protection.IsExecutable()) return Array.Empty<MemoryFinding>();
        if (region.Kind != MemoryRegionKind.Private) return Array.Empty<MemoryFinding>();
        if (sampleBytes is null || sampleBytes.Length < 256) return Array.Empty<MemoryFinding>();

        double entropy = ShannonEntropy(sampleBytes);
        if (entropy < _threshold) return Array.Empty<MemoryFinding>();

        return new[]
        {
            new MemoryFinding(
                kind: MemoryFindingKind.HighEntropyExecutable,
                processId: process?.ProcessId ?? 0,
                processName: process?.ProcessName ?? "",
                regionBase: region.BaseAddress,
                regionSize: region.Size,
                protection: region.Protection,
                regionKind: region.Kind,
                severity: MemoryScanSeverity.Low,
                description: $"Entropia alta ({entropy:F2} bits/byte) em região executável privada — " +
                             "indicador fraco (packers/criptografia).",
                scoreDelta: 2),
        };
    }

    internal static double ShannonEntropy(byte[] data)
    {
        if (data is null || data.Length == 0) return 0;
        Span<int> counts = stackalloc int[256];
        for (int i = 0; i < data.Length; i++) counts[data[i]]++;
        double total = data.Length;
        double e = 0;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            double p = counts[i] / total;
            e -= p * Math.Log2(p);
        }
        return e;
    }
}
