using System.Linq;
using DataVanger.Core;

namespace DataVanger.Detection.PE;

public static class PeCorrelationEngine
{
    public static void Analyze(PeAnalysisResult result)
    {
        var pe = result.File;
        if (pe is null) return;

        bool injection = PeImportAnalyzer.HasInjectionPattern(pe);
        bool dynamic = PeImportAnalyzer.HasDynamicResolution(pe);
        bool networkExec = PeImportAnalyzer.HasNetworkExecution(pe);
        bool rwx = pe.Sections.Any(s => s.Executable && s.Writable);
        bool packer = pe.PackerSectionCount > 0 || (pe.HighEntropyExecutableSectionCount > 0 && pe.ImportCount <= 3);
        bool payload = pe.OverlayPayload || pe.ResourcePayload;

        int signals = 0;
        if (injection) signals++;
        if (dynamic) signals++;
        if (networkExec) signals++;
        if (rwx) signals++;
        if (packer) signals++;
        if (payload) signals++;

        // BETA 11C — "forte" (High) now requires at least one STRUCTURAL signal (RWX / packer /
        // embedded payload), so a correlation of common imports alone (e.g. injection + dynamic +
        // network/exec) downgrades to "moderada" instead of strong correlation. This removes a
        // false-positive driver on API-heavy benign binaries without losing any structural signal
        // (the individual RWX/packer/payload evidence is unchanged). No risk threshold changed.
        bool structural = rwx || packer || payload;
        if (signals >= 3 && structural)
            result.Add("Correlação PE forte: múltiplos indicadores estáticos de loader/injeção/empacotamento", 4, EvidenceStrength.High);
        else if (signals >= 2)
            result.Add("Correlação PE moderada: indicadores estáticos combinados", 2, EvidenceStrength.Medium);
    }
}
