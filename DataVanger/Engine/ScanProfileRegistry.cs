using System;
using DataVanger.Analysis;
using DataVanger.Core;
using DataVanger.Detection;

namespace DataVanger.Engine;

/// <summary>
/// Centralized configuration for the 2-level profile system (Fast vs Deep).
///
/// Fast profile is user-initiated, minimal time, runs only fast/reliable detectors
/// (Hash, Persistence, Yara, Authenticode) on core user folders.
///
/// Deep profile is configurable, comprehensive scanning with all detection modules,
/// customizable target scope and analysis layers.
/// </summary>
public static class ScanProfileRegistry
{
    // Fast: Strictest gate (skip 90%+ of files); Deep: Raised gate to reduce false positives
    // FASE 6: Increased Deep minPreScore from 2 to 3 to suppress weak single-signal files
    public static int MinPreScore(ScanProfile profile) => profile switch
    {
        ScanProfile.Fast => 6,  // strictest: only clear signals survive
        ScanProfile.Deep => 3,  // raised: requires multiple weak signals or one strong signal
        _ => 3
    };

    // Signature check threshold (LOWER = check more signatures)
    public static int SignatureCheckThreshold(ScanProfile profile) => profile switch
    {
        ScanProfile.Fast => RiskThresholds.Suspect,  // 6: minimal signature checking for speed
        ScanProfile.Deep => 4,                        // deep: check more signatures
        _ => 4
    };

    public static int PersistenceThreshold(ScanProfile profile) => profile switch
    {
        ScanProfile.Fast => RiskThresholds.Suspect,  // 6: minimal persistence checks
        ScanProfile.Deep => 4,                        // deep: exhaustive persistence analysis
        _ => 4
    };

    /// <summary>
    /// Recommended worker-thread count for the parallel detection phase.
    ///
    /// Fast profile is most I/O-bound (minimal detection), so it gets maximum parallelism.
    /// Deep profile includes CPU-heavy archive decompression and document parsing, so it uses
    /// conservative cores/2 to balance throughput against machine saturation.
    ///
    /// Thread count never changes any verdict, threshold, score, or anti-FP decision — it only
    /// affects throughput.
    /// </summary>
    public static int RecommendedDegreeOfParallelism(ScanProfile profile, int processorCount)
    {
        int cores = Math.Max(1, processorCount);
        return profile switch
        {
            ScanProfile.Fast => Math.Clamp(cores, 8, 32),    // Max threads for I/O bound work
            ScanProfile.Deep => Math.Clamp(cores / 2, 2, 6), // Conservative for CPU-heavy work
            _ => Math.Clamp(cores / 2, 2, 6)
        };
    }

    /// <summary>
    /// Returns which detection modules should run for the given profile.
    /// Fast profile runs only fast/reliable modules (Hash, Persistence, Yara, Authenticode).
    /// Deep profile runs all 9 modules.
    /// </summary>
    public static DetectionModuleSet ModulesToRun(ScanProfile profile) => profile switch
    {
        ScanProfile.Fast => DetectionModuleSet.FastOnly(),
        ScanProfile.Deep => DetectionModuleSet.All(),
        _ => DetectionModuleSet.All()
    };

    /// <summary>
    /// Returns the analysis layer configuration (archives, documents, extensions, etc.)
    /// for the given profile and optional deep scan configuration.
    ///
    /// Fast profile never analyzes archives, documents, or extensions.
    /// Deep profile uses the provided DeepScanLayerConfig or default settings.
    /// </summary>
    public static AnalysisLayerConfig GetAnalysisLayers(ScanProfile profile, AppSettings settings,
        DeepScanLayerConfig? deepConfig)
    {
        if (profile == ScanProfile.Fast)
            return AnalysisLayerConfig.None();

        if (deepConfig != null)
        {
            return new AnalysisLayerConfig
            {
                ArchivesEnabled = deepConfig.AnalyzeArchives,
                ArchiveMaxDepth = deepConfig.ArchiveMaxDepth,
                DocumentsEnabled = deepConfig.AnalyzeDocuments,
                ExtensionsEnabled = deepConfig.AnalyzeBrowserExtensions,
                AlternateStreamsEnabled = deepConfig.AnalyzeAlternateDataStreams
            };
        }

        return new AnalysisLayerConfig
        {
            ArchivesEnabled = settings.DeepScanArchives,
            ArchiveMaxDepth = 3,
            DocumentsEnabled = settings.AnalyzeDocuments,
            ExtensionsEnabled = settings.AnalyzeBrowserExtensions,
            AlternateStreamsEnabled = false
        };
    }

    // Legacy compatibility: only Deep profile can scan archives/documents/extensions
    public static bool ScansArchives(ScanProfile profile, AppSettings settings, ScanOptions options) =>
        profile == ScanProfile.Deep
        && settings.DeepScanArchives
        && options.ScanArchives;

    public static bool ScansDocuments(ScanProfile profile, AppSettings settings, ScanOptions options) =>
        profile == ScanProfile.Deep
        && settings.AnalyzeDocuments
        && options.ScanDocuments;

    public static bool ScansBrowserExtensions(ScanProfile profile, AppSettings settings, ScanOptions options) =>
        profile == ScanProfile.Deep
        && settings.AnalyzeBrowserExtensions
        && options.ScanBrowserExtensions;
}
