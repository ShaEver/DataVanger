using System;
using System.IO;
using System.Linq;
using DataVanger.Core;

namespace DataVanger.Detection.PE;

public static class PeAnalyzer
{
    public static bool IsPeFile(string path) => PeParser.IsPeFile(path);
    public static bool IsPeFile(Stream stream) => PeParser.IsPeFile(stream);

    /// <summary>
    /// FASE 4 — Single path-based entry point returning both the scoring result and
    /// the parsed PE (which has section.Entropy already populated by PeSectionAnalyzer).
    /// This eliminates the need for a second open+parse in PeDetectionModule.
    /// </summary>
    public static (AnalysisResult Result, PeFile? Pe) AnalyzeWithFile(string path)
    {
        var result = new AnalysisResult();
        PeFile? parsed = null;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 81_920, useAsync: false);
            var pe = PeParser.Parse(stream, path);
            RunAnalyzers(stream, path, includeSignature: true, pe);
            Copy(pe, result);
            parsed = pe.File;  // section.Entropy already populated by PeSectionAnalyzer.Analyze
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Malformed PE or unreadable file - return the partial result unchanged; fatal CLR exceptions are not swallowed.
        }
        return (Deduplicate(result), parsed);
    }

    public static AnalysisResult Analyze(string path)
    {
        return AnalyzeWithFile(path).Result;
    }

    public static AnalysisResult Analyze(Stream stream, string logicalPath = "")
    {
        var result = new AnalysisResult();
        try
        {
            var pe = PeParser.Parse(stream, logicalPath);
            RunAnalyzers(stream, logicalPath, includeSignature: false, pe);
            Copy(pe, result);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Malformed PE stream - return the partial result unchanged; fatal CLR exceptions are not swallowed.
        }
        return Deduplicate(result);
    }

    private static void RunAnalyzers(Stream stream, string path, bool includeSignature, PeAnalysisResult result)
    {
        if (!result.IsPe || !result.ParsedSuccessfully || result.File is null) return;
        PeHeaderAnalyzer.Analyze(result);
        PeSectionAnalyzer.Analyze(stream, result);
        PeImportAnalyzer.Analyze(stream, result);
        PeOverlayAnalyzer.Analyze(stream, result);
        PeResourceAnalyzer.Analyze(stream, result);
        PeMetadataAnalyzer.Analyze(path, result);
        if (includeSignature) PeSignatureAnalyzer.Analyze(path, result);
        PeCorrelationEngine.Analyze(result);
    }

    private static void Copy(PeAnalysisResult source, AnalysisResult target)
    {
        foreach (var evidence in source.Evidence) target.Evidence.Add(evidence);
    }

    private static AnalysisResult Deduplicate(AnalysisResult result)
    {
        var clean = new AnalysisResult();
        foreach (var evidence in result.Evidence.GroupBy(e => e.Description, StringComparer.OrdinalIgnoreCase).Select(g => g.First()))
            clean.Evidence.Add(evidence);
        return clean;
    }
}
