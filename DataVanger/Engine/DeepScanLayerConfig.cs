using System;

namespace DataVanger.Engine;

public class DeepScanLayerConfig
{
    // Target scope layers (which areas to scan)
    public bool IncludeUserFolders { get; set; } = true;
    public bool IncludeSystemAreas { get; set; } = true;
    public bool IncludeProgramFiles { get; set; } = true;
    public bool IncludeRemovableDrives { get; set; } = false;

    // Analysis layers (what to analyze within targets)
    public bool AnalyzeArchives { get; set; } = true;
    public int ArchiveMaxDepth { get; set; } = 3;
    public long ArchiveMaxDecompressedMB { get; set; } = 256;

    public bool AnalyzeDocuments { get; set; } = true;
    public bool AnalyzeBrowserExtensions { get; set; } = true;
    public bool AnalyzeAlternateDataStreams { get; set; } = false;

    // Performance tuning
    public int? MaxDegreeOfParallelism { get; set; } = null;
    public int PerFileTimeoutSeconds { get; set; } = 120;

    // Preset configurations
    public static DeepScanLayerConfig Default => new()
    {
        IncludeUserFolders = true,
        IncludeSystemAreas = true,
        IncludeProgramFiles = true,
        IncludeRemovableDrives = false,
        AnalyzeArchives = true,
        ArchiveMaxDepth = 3,
        AnalyzeDocuments = true,
        AnalyzeBrowserExtensions = true,
        AnalyzeAlternateDataStreams = false
    };

    public static DeepScanLayerConfig FullDisk => new()
    {
        IncludeUserFolders = true,
        IncludeSystemAreas = true,
        IncludeProgramFiles = true,
        IncludeRemovableDrives = true,
        AnalyzeArchives = true,
        ArchiveMaxDepth = 6,
        AnalyzeDocuments = true,
        AnalyzeBrowserExtensions = true,
        AnalyzeAlternateDataStreams = true
    };

    public static DeepScanLayerConfig UserFoldersOnly => new()
    {
        IncludeUserFolders = true,
        IncludeSystemAreas = false,
        IncludeProgramFiles = false,
        IncludeRemovableDrives = false,
        AnalyzeArchives = true,
        ArchiveMaxDepth = 3,
        AnalyzeDocuments = true,
        AnalyzeBrowserExtensions = false,
        AnalyzeAlternateDataStreams = false
    };
}
