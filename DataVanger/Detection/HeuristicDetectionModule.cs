using System;
using System.Collections.Generic;
using System.Threading;
using DataVanger.Core;
using DataVanger.Core.Domain;

namespace DataVanger.Detection;

/// <summary>
/// Path/name/attribute/entropy heuristics. Always runs first so later modules
/// can react to the heuristic score (e.g. signature-trust check only when the
/// preliminary score is above a threshold).
///
/// All evidence emitted here is heuristic — the classifier guarantees it can
/// never produce ConfirmedMalware on its own.
/// </summary>
public sealed class HeuristicDetectionModule : DetectionModuleBase
{
    // Union of DangerExt + PeExt — matches the eligibility set the v3.0
    // engine fed into ComputeHeuristics. Archive/document/browser-extension
    // files are NOT scanned by the heuristic module (they have their own
    // content-aware modules and would only produce path noise here).
    private static readonly HashSet<string> EligibleExt = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".scr", ".com", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".ps1", ".psm1", ".msi", ".lnk", ".iso", ".img", ".dll", ".sys", ".hta", ".ocx", ".cpl" };

    public override string Name => "Heuristic";
    public override DetectionModuleCapabilities Capabilities =>
        DetectionModuleCapabilities.NeedsPath | DetectionModuleCapabilities.NeedsContent;

    public override bool Supports(ScanTarget target, ScanContext context) => EligibleExt.Contains(target.Extension);

    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
    {
        var result = HeuristicAnalyzer.Analyze(target, context);
        HeuristicAnalyzer.ApplyProtectedWindowsWeakSignalAttenuation(target, result);
        return FromAnalysisResult(result);
    }
}
