using System.Collections.Generic;
using System.Threading;
using DataVanger.Core;
using DataVanger.Core.Domain;

namespace DataVanger.Detection;

/// <summary>
/// Inspects ZIP-like archives (including Office Open XML containers) when
/// the active profile and settings allow archive scanning.
/// </summary>
public sealed class ArchiveDetectionModule : DetectionModuleBase
{
    public override string Name => "Archive";
    public override DetectionModuleCapabilities Capabilities =>
        DetectionModuleCapabilities.NeedsContent | DetectionModuleCapabilities.ArchiveAware;

    public override bool Supports(ScanTarget target, ScanContext context) =>
        context.Deep
        && context.Settings.DeepScanArchives
        && context.Options.ScanArchives
        && ArchiveAnalyzer.IsArchiveExtension(target.Extension);

    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
    {
        var result = ArchiveAnalyzer.Analyze(target.File, context.Settings.ArchiveMaxEntries);
        return FromAnalysisResult(result);
    }
}
