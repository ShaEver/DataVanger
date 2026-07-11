using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using DataVanger.Core;
using DataVanger.Core.Domain;

namespace DataVanger.Detection;

/// <summary>
/// Static PE analysis adapter. The parser/analyzers live in
/// <c>DataVanger.Detection.PE</c>; this module preserves the existing
/// detection pipeline registration point.
/// </summary>
public sealed class PeDetectionModule : DetectionModuleBase
{
    private static readonly HashSet<string> PeExt = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".efi", ".drv" };

    // ----- Phase 04: section-granular entropy observability (additive, descriptive-only) -----
    // Conservative private thresholds used ONLY to decide whether to DESCRIBE a section-level
    // entropy anomaly. They never feed scoring, classification, reporting gates, or quarantine.
    private const double HighTextSectionEntropy = 7.4;          // code/exec sections (.text, packer stubs)
    private const double HighDataSectionEntropy = 7.5;          // data sections (.data, .rdata, ...)
    private const double VeryHighSectionEntropy = 7.8;          // near-random: strong packing/encryption hint
    private const int MaxReportedSections = 6;                  // keep the descriptive summary concise

    public override string Name => "PeStatic";
    public override DetectionModuleCapabilities Capabilities =>
        DetectionModuleCapabilities.NeedsContent | DetectionModuleCapabilities.PeAware;

    public override bool Supports(ScanTarget target, ScanContext context)
    {
        if (PeExt.Contains(target.Extension)) return true;
        try
        {
            return target.File.Exists
                && target.File.Length >= 0x40
                && target.File.Length <= 256L * 1024 * 1024
                && PE.PeAnalyzer.IsPeFile(target.FullPath);
        }
        catch (System.Exception) { return false; }
    }

    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
    {
        // FASE 4 — single open+parse; section.Entropy already computed by PeSectionAnalyzer.Analyze
        var (result, pe) = PE.PeAnalyzer.AnalyzeWithFile(target.FullPath);
        var evidence = FromAnalysisResult(result);

        // Build the descriptive entropy map from the already-parsed sections (zero additional I/O).
        var sectionEntropy = BuildSectionEntropyMap(pe);
        return EnrichEvidenceWithSectionEntropy(evidence, sectionEntropy);
    }

    /// <summary>
    /// FASE 4 — Build the descriptive section-entropy map from the already-parsed PeFile,
    /// reusing the entropy values computed by PeSectionAnalyzer.Analyze during the first
    /// (and only) parse. Zero additional file I/O.
    /// </summary>
    private Dictionary<string, double> BuildSectionEntropyMap(PE.PeFile? pe)
    {
        var sectionEntropy = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        if (pe is null) return sectionEntropy;

        foreach (var section in pe.Sections)
        {
            // Skip sections that failed validation or have no raw data (same logic as PeSectionAnalyzer).
            if (section.RawSize == 0 || !section.RawRangeValid(pe.Length)) continue;

            // Reuse the entropy already computed by PeSectionAnalyzer (identical method, identical cap).
            string name = string.IsNullOrEmpty(section.Name) ? "<unnamed>" : section.Name;
            if (!sectionEntropy.TryGetValue(name, out var prev) || section.Entropy > prev)
                sectionEntropy[name] = section.Entropy;
        }

        return sectionEntropy;
    }

    /// <summary>
    /// Appends a single descriptive, non-scoring evidence line when
    /// <see cref="ComputeEntropyAnomalies"/> reports something noteworthy, and returns
    /// <paramref name="baseEvidence"/> unchanged otherwise. Never mutates the input list and never
    /// changes score, strength, or confirmation semantics of existing evidence.
    /// </summary>
    private IReadOnlyList<Evidence> EnrichEvidenceWithSectionEntropy(
        IReadOnlyList<Evidence> baseEvidence,
        Dictionary<string, double> sectionEntropy)
    {
        string anomalies = ComputeEntropyAnomalies(sectionEntropy);
        if (string.IsNullOrEmpty(anomalies)) return baseEvidence;

        var enriched = new List<Evidence>(baseEvidence)
        {
            new Evidence
            {
                Category = "PE",
                Description = anomalies,
                ScoreDelta = 0,                    // descriptive only - never changes the aggregated score
                Strength = EvidenceStrength.Info,  // never Confirmed - cannot promote to ConfirmedMalware
                CanConfirmMalware = false,
            }
        };
        return enriched;
    }

    /// <summary>
    /// Produces a concise, cautious description of section-level entropy anomalies, or an empty
    /// string when nothing is noteworthy. Uses the conservative private thresholds above and
    /// deliberately avoids verdict language (no "confirmed", no "malware", no quarantine wording).
    /// </summary>
    private string ComputeEntropyAnomalies(Dictionary<string, double> sectionEntropy)
    {
        if (sectionEntropy.Count == 0) return "";

        var flagged = new List<string>();
        bool packingHint = false;
        bool packerNamed = false;
        foreach (var pair in sectionEntropy)
        {
            string name = pair.Key;
            double entropy = pair.Value;
            bool isText = name.IndexOf("text", StringComparison.OrdinalIgnoreCase) >= 0;
            bool isData = name.EndsWith("data", StringComparison.OrdinalIgnoreCase);
            bool isPacker = PE.PeSectionAnalyzer.IsPackerSectionName(name);

            bool flag = entropy >= VeryHighSectionEntropy
                        || (isText && entropy >= HighTextSectionEntropy)
                        || (isData && entropy >= HighDataSectionEntropy)
                        || (isPacker && entropy >= HighTextSectionEntropy);
            if (!flag) continue;

            flagged.Add($"{name} ({entropy:F2})");
            if (entropy >= VeryHighSectionEntropy || isText || isPacker) packingHint = true;
            if (isPacker) packerNamed = true;
            if (flagged.Count >= MaxReportedSections) break;
        }

        if (flagged.Count == 0) return "";

        string list = string.Join(", ", flagged);
        string lead = flagged.Count > 1
            ? "Multiple PE sections show elevated entropy"
            : "Elevated entropy observed in PE section";
        string qualifier = packerNamed
            ? "consistent with packed payload structure"
            : packingHint
                ? "possible packing or encryption"
                : "above the expected section profile";
        return $"{lead}: {list}; {qualifier}.";
    }
}
