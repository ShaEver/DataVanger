using System;
using System.Linq;
using DataVanger.Core;
using DataVanger.Services;
using DataVanger.Shared.History;
using Xunit;

// Phase 07 live history wiring. The recorder writes scan/detection/quarantine events,
// but is honest: a scan never emits a verification event, so a quarantine is "done"
// (Succeeded) yet never reported verified.
public class ScanHistoryRecorderTests
{
    private static ScanFinding Confirmed(string path) => new() { Path = path, IsBlacklisted = true };
    private static ScanFinding HighRisk(string path) => new() { Path = path, Score = 10 };
    private static ScanFinding Clean(string path) => new() { Path = path, Score = 0 };
    private static ScanMetrics Metrics() => new() { TotalTime = TimeSpan.FromSeconds(2) };

    [Fact]
    public void RecordScanStarted_AppendsOneScanEvent()
    {
        var store = new HistoryStore();
        new ScanHistoryRecorder(store).RecordScanStarted("Quick");

        var all = store.All();
        Assert.Single(all);
        Assert.Equal(HistoryEventKind.Scan, all[0].Kind);
    }

    [Fact]
    public void RecordScanCompleted_AppendsSummary_AndDetectionsForActionableOnly()
    {
        var store = new HistoryStore();
        var autoQuarantined = Confirmed(@"C:\t\q.exe");
        autoQuarantined.WasQuarantined = true;
        var findings = new[] { Confirmed(@"C:\t\a.exe"), HighRisk(@"C:\t\b.exe"), Clean(@"C:\t\c.txt"), autoQuarantined };

        new ScanHistoryRecorder(store).RecordScanCompleted(findings, Metrics());

        var all = store.All();
        Assert.Equal(1, all.Count(e => e.Kind == HistoryEventKind.Scan));        // completion summary
        Assert.Equal(3, all.Count(e => e.Kind == HistoryEventKind.Detection));   // confirmed + high-risk + auto-quarantined; clean excluded
        Assert.Equal(1, all.Count(e => e.Kind == HistoryEventKind.RemediationAction));
        Assert.False(store.IsRemediationVerified(autoQuarantined.SHA256 ?? autoQuarantined.Path));
    }

    [Fact]
    public void Scan_NeverEmitsVerification_AndNeverMarksRemediationVerified()
    {
        var store = new HistoryStore();
        var finding = Confirmed(@"C:\t\a.exe");
        var recorder = new ScanHistoryRecorder(store);

        recorder.RecordScanCompleted(new[] { finding }, Metrics());
        recorder.RecordQuarantine(finding);

        Assert.DoesNotContain(store.All(), e => e.Kind == HistoryEventKind.Verification);
        var correlation = string.IsNullOrWhiteSpace(finding.SHA256) ? finding.Path : finding.SHA256;
        Assert.False(store.IsRemediationVerified(correlation));
    }

    [Fact]
    public void RecordQuarantine_RecordsSucceededRemediation_ButNotVerified()
    {
        var store = new HistoryStore();
        var finding = Confirmed(@"C:\t\a.exe");

        new ScanHistoryRecorder(store).RecordQuarantine(finding);

        var all = store.All();
        Assert.Single(all);
        Assert.Equal(HistoryEventKind.RemediationAction, all[0].Kind);
        Assert.Equal(HistoryOutcome.Succeeded, all[0].Outcome);
        Assert.False(store.IsRemediationVerified(finding.Path));
    }
}
