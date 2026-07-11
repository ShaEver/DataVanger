using System;
using System.IO;
using System.Linq;
using DataVanger.Shared.History;
using Xunit;

// Phase 07 — persistent threat/action history. Honesty contract: a remediation is
// never reported resolved until a passing verification event confirms it.
public class HistoryStoreTests
{
    [Fact]
    public void Append_And_All_RoundTrip_InOrder()
    {
        var store = new HistoryStore();
        store.Append(HistoryEvent.Scan("scan started"));
        store.Append(HistoryEvent.Detection("evil.exe", "corr-1"));

        var all = store.All();
        Assert.Equal(2, all.Count);
        Assert.Equal(HistoryEventKind.Scan, all[0].Kind);
        Assert.Equal(HistoryEventKind.Detection, all[1].Kind);
    }

    [Fact]
    public void ForCorrelation_FiltersByCorrelationId()
    {
        var store = new HistoryStore();
        store.Append(HistoryEvent.Detection("a", "corr-1"));
        store.Append(HistoryEvent.Detection("b", "corr-2"));
        store.Append(HistoryEvent.Remediation("quarantine", "corr-1", HistoryOutcome.Succeeded));

        Assert.Equal(2, store.ForCorrelation("corr-1").Count);
        Assert.Single(store.ForCorrelation("corr-2"));
    }

    [Fact]
    public void Remediation_Alone_IsNotReportedVerified_EvenWhenSucceeded()
    {
        var store = new HistoryStore();
        store.Append(HistoryEvent.Remediation("delete", "corr-1", HistoryOutcome.Succeeded));

        Assert.False(store.IsRemediationVerified("corr-1"));
    }

    [Fact]
    public void Remediation_WithFailedVerification_IsNotVerified()
    {
        var store = new HistoryStore();
        store.Append(HistoryEvent.Remediation("delete", "corr-1", HistoryOutcome.Succeeded));
        store.Append(HistoryEvent.Verification("verify", "corr-1", passed: false));

        Assert.False(store.IsRemediationVerified("corr-1"));
    }

    [Fact]
    public void Remediation_WithPassingVerification_IsVerified()
    {
        var store = new HistoryStore();
        store.Append(HistoryEvent.Remediation("delete", "corr-1", HistoryOutcome.Succeeded));
        store.Append(HistoryEvent.Verification("verify", "corr-1", passed: true));

        Assert.True(store.IsRemediationVerified("corr-1"));
    }

    [Fact]
    public void Verification_WithoutRemediation_IsNotConsideredVerifiedRemediation()
    {
        var store = new HistoryStore();
        store.Append(HistoryEvent.Verification("verify", "corr-1", passed: true));

        Assert.False(store.IsRemediationVerified("corr-1"));
    }

    [Fact]
    public void IsRemediationVerified_UnknownOrEmptyCorrelation_IsFalse()
    {
        var store = new HistoryStore();
        Assert.False(store.IsRemediationVerified("nope"));
        Assert.False(store.IsRemediationVerified(""));
    }

    [Fact]
    public void PathBacked_PersistsAndReloads()
    {
        var path = TempPath();
        try
        {
            var store = new HistoryStore(path);
            store.Append(HistoryEvent.Remediation("delete", "corr-1", HistoryOutcome.Succeeded));
            store.Append(HistoryEvent.Verification("verify", "corr-1", passed: true));

            var reloaded = new HistoryStore(path);
            Assert.Equal(2, reloaded.Count);
            Assert.True(reloaded.IsRemediationVerified("corr-1"));
            Assert.Equal("corr-1", reloaded.All().First().CorrelationId);
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void CorruptHistoryFile_StartsEmpty_WithoutThrowing()
    {
        var path = TempPath();
        try
        {
            File.WriteAllText(path, "{ this is not valid json ");
            var store = new HistoryStore(path);
            Assert.Equal(0, store.Count);
        }
        finally { Cleanup(path); }
    }

    private static string TempPath() =>
        Path.Combine(Path.GetTempPath(), "dvtest_history_" + Guid.NewGuid().ToString("N") + ".json");

    private static void Cleanup(string path)
    {
        try { File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
