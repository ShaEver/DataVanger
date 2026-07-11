using System;

namespace DataVanger.Analysis;

public class AnalysisLayerConfig
{
    public bool ArchivesEnabled { get; set; }
    public int ArchiveMaxDepth { get; set; }
    public bool DocumentsEnabled { get; set; }
    public bool ExtensionsEnabled { get; set; }
    public bool AlternateStreamsEnabled { get; set; }

    public static AnalysisLayerConfig None() => new()
    {
        ArchivesEnabled = false,
        DocumentsEnabled = false,
        ExtensionsEnabled = false,
        AlternateStreamsEnabled = false,
        ArchiveMaxDepth = 0
    };

    public static AnalysisLayerConfig Default() => new()
    {
        ArchivesEnabled = true,
        ArchiveMaxDepth = 3,
        DocumentsEnabled = true,
        ExtensionsEnabled = true,
        AlternateStreamsEnabled = false
    };

    public static AnalysisLayerConfig FullDisk() => new()
    {
        ArchivesEnabled = true,
        ArchiveMaxDepth = 6,
        DocumentsEnabled = true,
        ExtensionsEnabled = true,
        AlternateStreamsEnabled = true
    };
}
