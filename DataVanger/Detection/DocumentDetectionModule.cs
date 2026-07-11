using System;
using System.Collections.Generic;
using System.Threading;
using DataVanger.Core;
using DataVanger.Core.Domain;

namespace DataVanger.Detection;

/// <summary>Wraps <see cref="DocumentAnalyzer"/> (Office Open XML + PDF) as a module.</summary>
public sealed class DocumentDetectionModule : DetectionModuleBase
{
    private static readonly HashSet<string> DocumentExt = new(StringComparer.OrdinalIgnoreCase)
        { ".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptm", ".pptx", ".pdf", ".xlam" };

    public override string Name => "Document";
    public override DetectionModuleCapabilities Capabilities =>
        DetectionModuleCapabilities.NeedsContent | DetectionModuleCapabilities.DocumentAware;

    public override bool Supports(ScanTarget target, ScanContext context) =>
        context.Deep
        && context.Settings.AnalyzeDocuments
        && context.Options.ScanDocuments
        && DocumentExt.Contains(target.Extension);

    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
    {
        var result = DocumentAnalyzer.Analyze(target.FullPath);
        return FromAnalysisResult(result);
    }
}
