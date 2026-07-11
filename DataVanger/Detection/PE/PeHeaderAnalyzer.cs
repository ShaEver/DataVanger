using System;
using DataVanger.Core;

namespace DataVanger.Detection.PE;

public static class PeHeaderAnalyzer
{
    public static void Analyze(PeAnalysisResult result)
    {
        var pe = result.File;
        if (pe is null) return;

        result.Add($"PE {pe.Architecture}, {pe.Sections.Count} seção(ões), subsistema {pe.Subsystem}", 0, EvidenceStrength.Info);

        if (pe.Timestamp != 0)
        {
            var compile = DateTimeOffset.FromUnixTimeSeconds(pe.Timestamp).UtcDateTime;
            if (compile.Year < 1995 || compile > DateTime.UtcNow.AddDays(2))
                result.Add($"Timestamp de compilação anômalo: {compile:yyyy-MM-dd}", 1, EvidenceStrength.Low);
        }

        if (pe.FileAlignment == 0 || pe.SectionAlignment == 0 || pe.FileAlignment > pe.SectionAlignment || pe.FileAlignment > 0x10000)
            result.Add($"Alinhamento PE incomum (file={pe.FileAlignment}, section={pe.SectionAlignment})", 1, EvidenceStrength.Low);

        if (pe.SizeOfHeaders > 0 && pe.SizeOfHeaders < 0x200)
            result.Add($"Cabeçalho PE suspeitamente pequeno ({pe.SizeOfHeaders} bytes)", 1, EvidenceStrength.Low);

        var ep = pe.SectionForRva(pe.EntryPointRva);
        if (pe.EntryPointRva != 0 && ep is null)
            result.Add($"Entry point fora das seções mapeadas (RVA 0x{pe.EntryPointRva:X})", 4, EvidenceStrength.High);
        else if (ep is not null && PeSectionAnalyzer.IsPackerSectionName(ep.Name))
            result.Add($"Entry point em seção com nome associado a packer: {ep.Name}", 2, EvidenceStrength.Medium);
    }
}
