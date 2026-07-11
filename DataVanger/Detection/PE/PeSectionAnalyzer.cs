using System;
using System.Collections.Generic;
using System.IO;
using DataVanger.Core;

namespace DataVanger.Detection.PE;

public static class PeSectionAnalyzer
{
    private const int MaxEntropyBytes = 2 * 1024 * 1024;
    private static readonly HashSet<string> PackerSections = new(StringComparer.OrdinalIgnoreCase)
        { "upx", "upx0", "upx1", ".upx", ".aspack", ".packed", ".themida", ".vmp", ".vmp0", ".vmp1", ".mpress", ".petite", ".fsg", ".adata", ".ndata", "aspack", "mpress" };

    public static bool IsPackerSectionName(string name) => PackerSections.Contains(name ?? "");

    public static void Analyze(Stream stream, PeAnalysisResult result)
    {
        var pe = result.File;
        if (pe is null) return;

        for (int i = 0; i < pe.Sections.Count; i++)
        {
            var section = pe.Sections[i];
            if (!section.RawRangeValid(pe.Length))
            {
                result.Add($"Seção {section.Name} possui range bruto inválido", 1, EvidenceStrength.Low);
                continue;
            }

            if (section.RawSize > 0)
                section.Entropy = PeEntropyAnalyzer.Calculate(PeParser.ReadBytes(stream, section.RawPointer, (int)Math.Min(section.RawSize, MaxEntropyBytes)));

            if (IsPackerSectionName(section.Name))
            {
                pe.PackerSectionCount++;
                result.Add($"Nome de seção associado a packer: {section.Name}", 2, EvidenceStrength.Medium);
            }

            if (section.Executable && section.Writable)
                result.Add($"Seção executável e gravável (RWX): {section.Name}", 4, EvidenceStrength.High);
            else if (section.Writable && section.Name.Contains("text", StringComparison.OrdinalIgnoreCase))
                result.Add($"Seção de código marcada como gravável: {section.Name}", 2, EvidenceStrength.Medium);

            if (section.Executable && section.Entropy >= 7.2)
            {
                pe.HighEntropyExecutableSectionCount++;
                result.Add($"Alta entropia em seção executável {section.Name}: {section.Entropy:F2}", section.Entropy >= 7.6 ? 3 : 2, EvidenceStrength.Medium);
            }
            else if (section.Entropy >= 7.7 && section.RawSize >= 4096)
            {
                result.Add($"Alta entropia em seção {section.Name}: {section.Entropy:F2}", 1, EvidenceStrength.Low);
            }

            if (section.RawSize == 0 && section.VirtualSize > 4096 && section.Executable)
                result.Add($"Seção executável sem dados brutos: {section.Name}", 2, EvidenceStrength.Medium);

            for (int j = i + 1; j < pe.Sections.Count; j++)
            {
                if (section.OverlapsRaw(pe.Sections[j]))
                {
                    result.Add($"Seções com ranges sobrepostos: {section.Name} / {pe.Sections[j].Name}", 2, EvidenceStrength.Medium);
                    break;
                }
            }
        }

        if (pe.PackerSectionCount > 0 && pe.HighEntropyExecutableSectionCount > 0)
            result.Add("Indicadores combinados de packer: nome de seção + alta entropia executável", 2, EvidenceStrength.Medium);
    }
}
