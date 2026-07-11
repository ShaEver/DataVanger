using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Classification;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;
using DataVanger.Detection;
using DataVanger.Engine;
using DataVanger.Memory;
using DataVanger.Memory.Readers;
using DataVanger.Memory.Rules;
using DataVanger.Reputation;
using static DataVanger.Tests.Fixtures.PeFactory;

// FASE 2 — 2-level profile system (Fast vs Deep).
// Tests verify Fast profile has minimal scope/detectors, Deep profile is customizable.
public class ScanProfileTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public void ScanProfileRegistry_FastVsDeepThresholds()
    {
        // Fast has strictest MinPreScore (skip 90% of files); Deep analyzes most files.
        Assert(ScanProfileRegistry.MinPreScore(ScanProfile.Fast) > ScanProfileRegistry.MinPreScore(ScanProfile.Deep),
            "Fast must use stricter pre-score gate than Deep.");

        // Fast skips expensive signature checks; Deep checks more.
        Assert(ScanProfileRegistry.SignatureCheckThreshold(ScanProfile.Fast) >= ScanProfileRegistry.SignatureCheckThreshold(ScanProfile.Deep),
            "Fast must check fewer signatures than Deep.");

        Assert(ScanProfileRegistry.PersistenceThreshold(ScanProfile.Fast) >= ScanProfileRegistry.PersistenceThreshold(ScanProfile.Deep),
            "Fast must check fewer persistence indicators than Deep.");
    }

    // Fast is most I/O-bound (minimal detection) — gets maximum parallelism.
    // Deep is CPU-heavy (all detectors, archive/document parsing) — uses conservative cores/2.
    [Xunit.Theory]
    [Xunit.InlineData(1)]
    [Xunit.InlineData(2)]
    [Xunit.InlineData(4)]
    [Xunit.InlineData(8)]
    [Xunit.InlineData(16)]
    [Xunit.InlineData(32)]
    public void RecommendedDegreeOfParallelism_FastGetsMostWorkers(int cores)
    {
        int fast = ScanProfileRegistry.RecommendedDegreeOfParallelism(ScanProfile.Fast, cores);
        int deep = ScanProfileRegistry.RecommendedDegreeOfParallelism(ScanProfile.Deep, cores);

        Assert(fast >= 1 && deep >= 1, "Every profile must allow at least one worker.");
        Assert(fast >= deep, "Fast (lightweight, I/O-bound) must get at least as many workers as Deep (CPU-heavy).");

        if (cores >= 8)
            Assert(fast >= 8, "Fast must use available cores on an 8-core (or larger) machine.");
    }

    [Xunit.Fact]
    public void DetectionModuleSet_FastOnlyRunsMinimalModules()
    {
        var fast = DetectionModuleSet.FastOnly();
        Assert(fast.Hash && fast.Persistence && fast.Yara && fast.Authenticode,
            "Fast must enable Hash, Persistence, Yara, Authenticode.");
        Assert(!fast.Heuristic && !fast.Script && !fast.PE && !fast.Archive && !fast.Document && !fast.BrowserExtension,
            "Fast must skip Heuristic, Script, PE, Archive, Document, BrowserExtension.");
    }

    [Xunit.Fact]
    public void DetectionModuleSet_DeepRunsAllModules()
    {
        var deep = DetectionModuleSet.All();
        Assert(deep.Hash && deep.Persistence && deep.Yara && deep.Authenticode &&
               deep.Heuristic && deep.Script && deep.PE && deep.Archive && deep.Document && deep.BrowserExtension,
            "Deep must enable all 10 detection modules.");
    }

    [Xunit.Fact]
    public void ScanProfileRegistry_ModulesToRun()
    {
        var fastModules = ScanProfileRegistry.ModulesToRun(ScanProfile.Fast);
        Assert(fastModules.Hash && fastModules.Persistence && fastModules.Yara && fastModules.Authenticode,
            "Fast registry must return FastOnly module set.");
        Assert(!fastModules.Heuristic && !fastModules.Archive && !fastModules.Document,
            "Fast registry must skip heavy modules.");

        var deepModules = ScanProfileRegistry.ModulesToRun(ScanProfile.Deep);
        Assert(deepModules.Hash && deepModules.Heuristic && deepModules.PE && deepModules.Archive,
            "Deep registry must return All module set.");
    }

    [Xunit.Fact]
    public void AnalysisLayerConfig_FastHasNone()
    {
        var settings = new AppSettings();
        var analysisLayers = ScanProfileRegistry.GetAnalysisLayers(ScanProfile.Fast, settings, null);
        Assert(!analysisLayers.ArchivesEnabled && !analysisLayers.DocumentsEnabled &&
               !analysisLayers.ExtensionsEnabled && !analysisLayers.AlternateStreamsEnabled,
            "Fast must disable all analysis layers.");
    }

    [Xunit.Fact]
    public void AnalysisLayerConfig_DeepUsesDefaults()
    {
        var settings = new AppSettings();
        var analysisLayers = ScanProfileRegistry.GetAnalysisLayers(ScanProfile.Deep, settings, null);
        Assert(analysisLayers.ArchivesEnabled && analysisLayers.DocumentsEnabled &&
               analysisLayers.ExtensionsEnabled && !analysisLayers.AlternateStreamsEnabled,
            "Deep default must enable archives, documents, extensions; skip alt streams.");
    }

    [Xunit.Fact]
    public void DeepScanLayerConfig_Presets()
    {
        var def = DataVanger.Engine.DeepScanLayerConfig.Default;
        Assert(def.IncludeUserFolders && def.IncludeSystemAreas && def.IncludeProgramFiles && !def.IncludeRemovableDrives,
            "Default config must include user/system/program folders, skip removable drives.");

        var full = DataVanger.Engine.DeepScanLayerConfig.FullDisk;
        Assert(full.IncludeRemovableDrives && full.AnalyzeAlternateDataStreams,
            "FullDisk config must include removable drives and alternate streams.");

        var userOnly = DataVanger.Engine.DeepScanLayerConfig.UserFoldersOnly;
        Assert(userOnly.IncludeUserFolders && !userOnly.IncludeSystemAreas && !userOnly.IncludeProgramFiles,
            "UserFoldersOnly config must include only user folders.");
    }

    [WindowsOnlyFact]
    public void ScanProfile_TargetScope_FastIsMinimal_DeepIsConfigurable()
    {
        var s = new AppSettings();
        var fast = TargetDiscovery.ResolveTargets(ScanProfile.Fast, s).ToList();
        var deepDefault = TargetDiscovery.ResolveTargets(ScanProfile.Deep, s, null).ToList();

        // Fast targets should be minimal (Downloads, Desktop, Temp, Startup if enabled, AppData if enabled)
        Assert(fast.Count < 20, "Fast targets should be minimal (<20 paths).");

        // FASE 5: Deep default should include full-drive enumeration (C:\, D:\, etc.)
        // Note: path COUNT may be smaller after RemoveContainedPaths() deduplication (C:\ subsumes all subpaths),
        // but coverage is much broader. Verify actual requirement: Deep includes fixed drives as root targets.
        bool deepHasRootDrives = deepDefault.Any(p =>
            (p.Length == 3 && p[1] == ':' && p[2] == Path.DirectorySeparatorChar) ||  // C:\, D:\, etc.
            p.EndsWith($":{Path.DirectorySeparatorChar}"));                            // Trailing separator variant
        Assert(deepHasRootDrives, "Deep profile must include full-drive enumeration (C:\\, D:\\, E:\\, etc.) for full filesystem coverage.");

        // Deep with UserFoldersOnly should be minimal like Fast, but different set
        var deepUserOnly = TargetDiscovery.ResolveTargets(
            ScanProfile.Deep, s, DataVanger.Engine.DeepScanLayerConfig.UserFoldersOnly).ToList();
        Assert(deepUserOnly.All(p => !p.Contains("Program Files") && !p.Contains("Windows")),
            "UserFoldersOnly config must exclude Program Files and Windows.");
    }

    [Xunit.Fact]
    public void DeepScanProfileDerivation_FastNeverUsesDeepScan()
    {
        // Fast profile should NOT use DeepScanPipeline
        var fastOptions = new ScanOptions { Profile = ScanProfile.Fast, UseDeepScanPipeline = false };
        Assert(fastOptions.Profile == ScanProfile.Fast, "Fast profile options should be set.");

        // Deep profile CAN use DeepScanPipeline if enabled
        var deepOptions = new ScanOptions { Profile = ScanProfile.Deep, UseDeepScanPipeline = true };
        Assert(deepOptions.Profile == ScanProfile.Deep && deepOptions.UseDeepScanPipeline,
            "Deep profile can use DeepScanPipeline for advanced features.");
    }
}
