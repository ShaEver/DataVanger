using System;
using System.Collections.Generic;
using System.Threading;
using DataVanger.BrowserIntelligence;
using DataVanger.Core;
using DataVanger.Core.Domain;

namespace DataVanger.Detection;

/// <summary>
/// Bridges the scan pipeline to <see cref="BrowserExtensionIntelligence"/>.
///
/// The module fires only on a <c>manifest.json</c> file living in an
/// extension-aware path. The heavy lifting (manifest parsing, bundler
/// detection, trust scoring) is delegated to the intelligence engine,
/// which is explicitly designed to:
///   - never confirm malware on static evidence,
///   - downgrade scores when the bundle clearly comes from a legitimate
///     frontend build (webpack/vite/React/Vue/Angular),
///   - keep browser-context, extension id and permissions in the
///     evidence stream so reports remain explainable.
/// </summary>
public sealed class BrowserExtensionDetectionModule : DetectionModuleBase
{
    public override string Name => "BrowserExtension";
    public override DetectionModuleCapabilities Capabilities =>
        DetectionModuleCapabilities.NeedsContent | DetectionModuleCapabilities.BrowserExtensionAware;

    public override bool Supports(ScanTarget target, ScanContext context) =>
        context.Deep
        && context.Settings.AnalyzeBrowserExtensions
        && context.Options.ScanBrowserExtensions
        && target.FileName.Equals("manifest.json", StringComparison.OrdinalIgnoreCase);

    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
    {
        var result = BrowserExtensionIntelligence.AnalyzeManifest(target.FullPath);
        return FromAnalysisResult(result);
    }
}
