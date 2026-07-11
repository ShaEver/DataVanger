using System;
using System.Collections.Generic;
using System.Threading;
using DataVanger.Core;
using DataVanger.Core.Domain;

namespace DataVanger.Detection;

/// <summary>
/// Wraps <see cref="ScriptAnalyzer"/> as a detection module.
///
/// All evidence here is heuristic — none of it can confirm malware on its
/// own. The classifier enforces that contract; this module is content with
/// emitting raw findings.
/// </summary>
public sealed class ScriptDetectionModule : DetectionModuleBase
{
    private static readonly HashSet<string> ScriptExt = new(StringComparer.OrdinalIgnoreCase)
        { ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".ps1", ".psm1", ".hta" };

    public override string Name => "Script";
    public override DetectionModuleCapabilities Capabilities =>
        DetectionModuleCapabilities.NeedsContent | DetectionModuleCapabilities.ScriptAware;

    public override bool Supports(ScanTarget target, ScanContext context) =>
        ScriptExt.Contains(target.Extension);

    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
    {
        // A path/container cannot suppress script-content analysis.
        var result = ScriptAnalyzer.AnalyzeFile(target.FullPath, benignContainer: false);
        return FromAnalysisResult(result);
    }
}
