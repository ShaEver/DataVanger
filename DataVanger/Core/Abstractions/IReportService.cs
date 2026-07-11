using System;
using System.Collections.Generic;
using DataVanger.Core;
using DataVanger.Reporting.Forensics;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// Renders scan results to user-visible formats (CSV, TXT, HTML, JSON).
/// Format selection comes from <see cref="ScanOptions.ReportFormat"/>.
///
/// The forensic surface (<see cref="BuildForensicReport"/> and friends)
/// is additive — legacy callers that only need the flat CSV/HTML/JSON
/// reports keep working unchanged.
/// </summary>
public interface IReportService
{
    void WriteCsv(string path, IReadOnlyList<ScanFinding> findings);
    void WriteTxt(string path, IReadOnlyList<ScanFinding> findings, ScanMetrics metrics, ScanOptions options);
    void WriteHtml(string path, IReadOnlyList<ScanFinding> findings, ScanMetrics metrics, ScanOptions options, DateTime scanDate);
    void WriteJson(string path, IReadOnlyList<ScanFinding> findings, ScanMetrics metrics, ScanOptions options, DateTime scanDate);

    /// <summary>
    /// Builds an in-memory forensic report from heterogeneous module
    /// inputs (scan findings, behavioural events, memory findings, runtime
    /// telemetry, scheduler executions). The result is safe to serialise.
    /// </summary>
    ForensicReport BuildForensicReport(ForensicReportInput input);

    /// <summary>Persists the forensic report as JSON.</summary>
    void WriteForensicJson(string path, ForensicReport report);

    /// <summary>Persists the forensic report as HTML with anti-XSS escaping.</summary>
    void WriteForensicHtml(string path, ForensicReport report);

    /// <summary>Persists an incident-level CSV view of the forensic report.</summary>
    void WriteForensicCsv(string path, ForensicReport report);
}
