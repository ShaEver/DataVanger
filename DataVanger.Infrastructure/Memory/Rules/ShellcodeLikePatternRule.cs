using System;
using System.Collections.Generic;
using System.Threading;

namespace DataVanger.Memory.Rules;

/// <summary>
/// Layered shellcode-pattern heuristic: looks for executable bytes that
/// either (a) contain a long NOP sled or (b) contain a typical x64
/// decoder stub prologue. Emits Medium severity at most — false
/// positives here are extremely easy with native code.
/// </summary>
public sealed class ShellcodeLikePatternRule : IMemoryRule
{
    private const int NopSledThreshold = 32;

    public string RuleId => "Memory.ShellcodeLike";
    public string Title => "Shellcode-like patterns in private executable memory";
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
        if (sampleBytes is null || sampleBytes.Length < 16) return Array.Empty<MemoryFinding>();

        bool nopSled = HasNopSled(sampleBytes);
        bool decoderStub = LooksLikeDecoderStub(sampleBytes);
        if (!nopSled && !decoderStub) return Array.Empty<MemoryFinding>();

        string what = nopSled && decoderStub
            ? "NOP-sled + stub-like prólogo"
            : nopSled ? "NOP-sled longo" : "prólogo de decoder/stub";

        return new[]
        {
            new MemoryFinding(
                kind: MemoryFindingKind.ShellcodeLikePattern,
                processId: process?.ProcessId ?? 0,
                processName: process?.ProcessName ?? "",
                regionBase: region.BaseAddress,
                regionSize: region.Size,
                protection: region.Protection,
                regionKind: region.Kind,
                severity: MemoryScanSeverity.Medium,
                description: $"Padrão tipo-shellcode em 0x{region.BaseAddress:X}: {what}. Heurístico.",
                scoreDelta: 3),
        };
    }

    private static bool HasNopSled(byte[] bytes)
    {
        int run = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] == 0x90) // x86/x64 NOP
            {
                if (++run >= NopSledThreshold) return true;
            }
            else
            {
                run = 0;
            }
        }
        return false;
    }

    private static bool LooksLikeDecoderStub(byte[] bytes)
    {
        // Very narrow signature set chosen to keep FP rate low:
        //   FC 48 83 E4 F0     -> cld; and rsp, -16     (PIC prologue)
        //   E8 00 00 00 00 5D  -> call $+5; pop rbp     (classic position-independent locator)
        if (bytes.Length >= 5
            && bytes[0] == 0xFC && bytes[1] == 0x48 && bytes[2] == 0x83
            && bytes[3] == 0xE4 && bytes[4] == 0xF0)
            return true;
        for (int i = 0; i + 6 <= bytes.Length; i++)
        {
            if (bytes[i] == 0xE8
                && bytes[i + 1] == 0x00 && bytes[i + 2] == 0x00
                && bytes[i + 3] == 0x00 && bytes[i + 4] == 0x00
                && bytes[i + 5] == 0x5D)
                return true;
        }
        return false;
    }
}
