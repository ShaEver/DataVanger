using System;
using System.Collections.Generic;
using System.Linq;
using DataVanger.Core;
using DataVanger.Shared.History;

namespace DataVanger.Services;

/// <summary>
/// Records scan and detection events into the persistent <see cref="HistoryStore"/>
/// (Phase 07 live wiring). Honest by construction:
/// <list type="bullet">
///   <item>A scan NEVER emits a verification event, so a quarantine recorded during a
///   scan is shown as <c>Succeeded</c> (done) but is never reported as verified — a
///   remediation is only "verified" after a separate passing verification event
///   (<see cref="HistoryStore.IsRemediationVerified"/>).</item>
///   <item>Every append is best-effort and exception-safe: a history write/build
///   failure must never block, slow, or abort a scan or remediation.</item>
/// </list>
/// It is WPF-free, so the recording logic is unit-tested without a UI host.
/// </summary>
public sealed class ScanHistoryRecorder
{
    private readonly HistoryStore _store;

    public ScanHistoryRecorder(HistoryStore store)
        => _store = store ?? throw new ArgumentNullException(nameof(store));

    public void RecordScanStarted(string profile)
        => Safe(() => _store.Append(HistoryEvent.Scan($"Varredura iniciada — perfil {profile}")));

    public void RecordScanCompleted(IReadOnlyList<ScanFinding> findings, ScanMetrics metrics)
        => Safe(() =>
        {
            int total = findings.Count;
            int confirmed = findings.Count(f => f.IsConfirmedMalware);
            int actionable = findings.Count(IsActionable);

            _store.Append(HistoryEvent.Scan(
                $"Varredura concluída: {total} achado(s), {confirmed} confirmado(s), {actionable} pendente(s)",
                $"Tempo {metrics.TotalTime.TotalSeconds:F1}s"));

            foreach (var finding in findings.Where(IsDetectionWorthRecording))
                _store.Append(HistoryEvent.Detection(
                    string.IsNullOrWhiteSpace(finding.FileName) ? "(arquivo)" : finding.FileName,
                    Correlation(finding),
                    $"{finding.RiskLabel}: {finding.Path}"));

            foreach (var finding in findings.Where(f => f.WasQuarantined))
                AppendQuarantine(finding);
        });

    /// <summary>Records a quarantine action as done — NOT verified (no verification
    /// occurs during a scan; verification is a later, separate event).</summary>
    public void RecordQuarantine(ScanFinding finding)
        => Safe(() => AppendQuarantine(finding));

    /// <summary>A finding the user still needs to act on: not yet quarantined and either
    /// confirmed malware or at/above the high-risk threshold.</summary>
    private static bool IsActionable(ScanFinding finding)
        => !finding.WasQuarantined && (finding.IsConfirmedMalware || finding.Score >= RiskThresholds.High);

    private static bool IsDetectionWorthRecording(ScanFinding finding)
        => finding.IsConfirmedMalware || finding.Score >= RiskThresholds.High || finding.WasQuarantined;

    private void AppendQuarantine(ScanFinding finding)
        => _store.Append(HistoryEvent.Remediation(
            $"Quarentena: {(string.IsNullOrWhiteSpace(finding.FileName) ? "(arquivo)" : finding.FileName)}",
            Correlation(finding),
            HistoryOutcome.Succeeded,
            finding.Path));

    private static string Correlation(ScanFinding finding)
        => string.IsNullOrWhiteSpace(finding.SHA256) ? (finding.Path ?? string.Empty) : finding.SHA256!;

    private static void Safe(Action action)
    {
        try { action(); }
        catch (Exception ex) when (
            ex is not OutOfMemoryException
            and not StackOverflowException
            and not System.Threading.ThreadAbortException)
        {
            // History is best-effort; a write/build failure must never block a scan.
        }
    }
}
