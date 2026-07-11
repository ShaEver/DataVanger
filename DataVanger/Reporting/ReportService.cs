using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Reporting.Forensics;

namespace DataVanger.Reporting;

/// <summary>
/// Adapter around the existing static <see cref="ReportGenerator"/> plus
/// the new <see cref="ForensicReportBuilder"/> / <see cref="ForensicReportExporter"/>.
///
/// Exists so the engine can depend on <see cref="IReportService"/> rather
/// than on a static class. The legacy static methods are kept intact —
/// other call sites can migrate to the interface incrementally.
/// </summary>
public sealed class ReportService : IReportService
{
    private readonly ForensicReportBuilder _forensicBuilder = new();
    private readonly ForensicReportExporter _forensicExporter = new();

    public void WriteCsv(string path, IReadOnlyList<ScanFinding> findings)
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("FileName,Risk,Type,SHA256,Signature,Path,RecommendedAction,Ext,SizeKB,Signed,Publisher,Score,Reasons,LastWrite,IsNew,IsBlacklisted,HasConfirmedSignature,WasQuarantined,ReputationState,ReputationScore,ReputationDelta,ReputationSeenCount,ReputationSignerStatus,ReputationUserDecision,ReputationReasons");
            foreach (var f in findings)
            {
                // Phase 07 — CSV export hardening: every attacker-influenceable string
                // field goes through CsvSafe (formula-injection + RFC 4180 quoting);
                // numeric/boolean columns stay plain so they keep their numeric form.
                sb.AppendLine(string.Join(",", new[]
                {
                    CsvSafe.Field(f.FileName),
                    CsvSafe.Field(f.RiskLabel),
                    CsvSafe.Field(f.Extension),
                    CsvSafe.Field(f.SHA256 ?? ""),
                    CsvSafe.Field(f.SignatureName),
                    CsvSafe.Field(f.Path),
                    CsvSafe.Field(f.RecommendedAction),
                    CsvSafe.Field(f.Extension),
                    f.SizeKB.ToString(),
                    f.IsSigned.ToString(),
                    CsvSafe.Field(f.Publisher),
                    f.Score.ToString(),
                    CsvSafe.Field(f.Reasons),
                    f.LastWrite.ToString("o"),
                    f.IsNew.ToString(),
                    f.IsBlacklisted.ToString(),
                    f.HasConfirmedSignature.ToString(),
                    f.WasQuarantined.ToString(),
                    CsvSafe.Field(f.ReputationState.ToString()),
                    f.ReputationScore.ToString(),
                    f.ReputationScoreDelta.ToString(),
                    f.ReputationSeenCount.ToString(),
                    CsvSafe.Field(f.ReputationSignerStatus),
                    CsvSafe.Field(f.ReputationUserDecision),
                    CsvSafe.Field(string.Join("; ", f.ReputationReasons)),
                }));
            }
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Report artifact failed to persist - make the failure observable without aborting the scan.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to write CSV report '{path}': {ex.Message}");
        }
    }

    public void WriteTxt(string path, IReadOnlyList<ScanFinding> findings, ScanMetrics metrics, ScanOptions options)
    {
        // Delegated to engine for now — kept here as a hook for future
        // format-specific summaries (Markdown, SARIF) without touching engine.
    }

    public void WriteHtml(string path, IReadOnlyList<ScanFinding> findings, ScanMetrics metrics, ScanOptions options, DateTime scanDate)
        => ReportGenerator.WriteHtml(path, findings.ToList(), metrics, options, scanDate);

    public void WriteJson(string path, IReadOnlyList<ScanFinding> findings, ScanMetrics metrics, ScanOptions options, DateTime scanDate)
        => ReportGenerator.WriteJson(path, findings.ToList(), metrics, options, scanDate);

    public ForensicReport BuildForensicReport(ForensicReportInput input)
        => _forensicBuilder.Build(input);

    public void WriteForensicJson(string path, ForensicReport report)
    {
        try { _forensicExporter.WriteJson(path, report); }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Forensic report artifact failed to persist - make the failure observable without aborting the scan.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to write forensic JSON '{path}': {ex.Message}");
        }
    }

    public void WriteForensicHtml(string path, ForensicReport report)
    {
        try { _forensicExporter.WriteHtml(path, report); }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Forensic report artifact failed to persist - make the failure observable without aborting the scan.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to write forensic HTML '{path}': {ex.Message}");
        }
    }

    public void WriteForensicCsv(string path, ForensicReport report)
    {
        try { _forensicExporter.WriteCsv(path, report); }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Forensic report artifact failed to persist - make the failure observable without aborting the scan.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to write forensic CSV '{path}': {ex.Message}");
        }
    }
}
