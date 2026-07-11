using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Scheduling.Abstractions;
using DataVanger.Scheduling.Models;

namespace DataVanger.Scheduling;

/// <summary>
/// Adapts the existing <see cref="IScanEngine"/> for scheduled execution.
/// Translates a <see cref="ScheduledJobDefinition"/> into
/// <see cref="ScanOptions"/>, runs the scan, and optionally writes a
/// scheduled report via <see cref="IReportService"/>.
///
/// Anti-FP contract:
///   * No findings are reclassified or escalated here.
///   * AutoQuarantine defers to <see cref="ScanOptions.AutoQuarantine"/>
///     which the engine itself only applies to <c>ConfirmedMalware</c>.
///   * A failed run is reported as <see cref="JobRunOutcome.Failed"/>
///     and never as a threat indicator.
/// </summary>
public sealed class ScanEngineScheduledRunner : IScheduledScanRunner
{
    private readonly IScanEngine _engine;
    private readonly IReportService? _reports;
    private readonly Action<string>? _log;
    private readonly string? _reportRoot;

    public ScanEngineScheduledRunner(
        IScanEngine engine,
        IReportService? reports = null,
        string? reportRoot = null,
        Action<string>? log = null)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _reports = reports;
        _reportRoot = reportRoot;
        _log = log;
    }

    public async Task<ScheduledRunResult> RunAsync(
        ScheduledJobDefinition job,
        CancellationToken cancellationToken)
    {
        if (job == null) return ScheduledRunResult.Skipped("Null job definition.");

        var options = new ScanOptions
        {
            Profile = job.Profile,
            Target = job.Target,
            ReportFormat = job.ReportFormat,
            // The scheduler never escalates: AutoQuarantine stays on the engine
            // default so anti-FP rules in ThreatClassificationPolicy keep precedence.
        };

        List<ScanFinding> findings;
        ScanMetrics metrics;
        try
        {
            (findings, metrics) = await _engine.RunAsync(
                options,
                LogLine,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return ScheduledRunResult.Cancelled();
        }

        string? reportPath = TryWriteScheduledReport(job, findings, metrics, options);

        return new ScheduledRunResult
        {
            Outcome = JobRunOutcome.Success,
            FindingsCount = findings?.Count ?? 0,
            Message = $"Scan completed: {metrics?.Findings ?? findings?.Count ?? 0} finding(s).",
            ReportPath = reportPath,
        };
    }

    private string? TryWriteScheduledReport(
        ScheduledJobDefinition job,
        List<ScanFinding> findings,
        ScanMetrics metrics,
        ScanOptions options)
    {
        if (_reports == null || string.IsNullOrWhiteSpace(_reportRoot)) return null;
        if (findings == null || findings.Count == 0) return null;
        try
        {
            Directory.CreateDirectory(_reportRoot!);
            var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            var safeName = new string((job.Name ?? "scheduled")
                .Select(c => char.IsLetterOrDigit(c) ? c : '_').ToArray());
            var path = Path.Combine(_reportRoot!, $"scheduled_{safeName}_{stamp}.csv");
            _reports.WriteCsv(path, findings);
            return path;
        }
        catch (Exception ex)
        {
            LogLine($"[scheduler] report write failed: {ex.Message}");
            return null;
        }
    }

    private void LogLine(string s)
    {
        try { _log?.Invoke(s); } catch (Exception) { /* Logger sink must never throw back to callers - swallow intentionally. */ }
    }
}
