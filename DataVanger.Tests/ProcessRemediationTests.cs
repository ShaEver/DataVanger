using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.SystemScope;
using Xunit;

// Phase 03C — process remediation tests (fake provider only; no real kills).
// Filter: ~Remediation.
public class ProcessRemediationTests
{
    private sealed class FixedClock : IRemediationClock
    {
        public DateTimeOffset UtcNow { get; set; } = new(2026, 6, 13, 0, 0, 0, TimeSpan.Zero);
    }

    private sealed class FakeProcessProvider : IProcessRemediationProvider
    {
        public int CurrentProcessId { get; init; } = 999;
        public Dictionary<int, ProcessIdentitySnapshot> Identities { get; } = new();
        public Dictionary<int, List<int>> Children { get; } = new();
        public List<int> Killed { get; } = new();
        public bool ThrowOnKill { get; init; }

        public ProcessIdentitySnapshot? GetIdentity(int pid)
            => Identities.TryGetValue(pid, out var id) ? id : null;

        public IReadOnlyList<int> GetChildren(int pid)
            => Children.TryGetValue(pid, out var c) ? c : new List<int>();

        public void Kill(int pid)
        {
            if (ThrowOnKill) throw new InvalidOperationException("simulated kill failure");
            Killed.Add(pid);
        }
    }

    private static FakeProcessProvider WithProcess(int pid, string name, IEnumerable<int>? children = null)
    {
        var p = new FakeProcessProvider();
        p.Identities[pid] = new ProcessIdentitySnapshot(pid, name, $@"C:\Temp\{name}");
        if (children is not null) p.Children[pid] = children.ToList();
        return p;
    }

    // ── Positive ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Kill_NonCriticalTree_RecordsAffectedIdentities_KillsLeavesFirst()
    {
        var p = WithProcess(1000, "evil.exe", new[] { 1001, 1002 });
        p.Identities[1001] = new ProcessIdentitySnapshot(1001, "evilchild1.exe", @"C:\Temp\c1");
        p.Identities[1002] = new ProcessIdentitySnapshot(1002, "evilchild2.exe", @"C:\Temp\c2");

        var action = new KillProcessTreeAction(p, clock: new FixedClock());
        var journal = new InMemoryRemediationJournal();

        var result = await action.ExecuteAsync(new ProcessRemediationTarget { Pid = 1000 }, journal, RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.Succeeded, result.Outcome);
        Assert.Equal(3, result.AffectedIdentities.Count);
        // Leaves before root.
        Assert.True(p.Killed.IndexOf(1000) > p.Killed.IndexOf(1001));
        // Irreversible: no recoverable rollback token.
        Assert.False(result.RollbackToken?.CanRollback ?? false);
    }

    [Fact]
    public async Task Kill_JournalsIntentBeforeOutcome()
    {
        var p = WithProcess(1000, "evil.exe");
        var action = new KillProcessTreeAction(p, clock: new FixedClock());
        var journal = new InMemoryRemediationJournal();
        var corr = RemediationCorrelationId.New();

        await action.ExecuteAsync(new ProcessRemediationTarget { Pid = 1000 }, journal, corr);

        var records = journal.ForCorrelation(corr);
        Assert.Equal(2, records.Count);
        Assert.Equal(RemediationJournalEntryKind.Intent, records[0].EntryKind);
        Assert.Equal(RemediationJournalEntryKind.Outcome, records[1].EntryKind);
    }

    // ── Negative: critical / unknown / self ─────────────────────────────────

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    public async Task Kill_Refuses_SystemPids(int pid)
    {
        var p = new FakeProcessProvider();
        var action = new KillProcessTreeAction(p, clock: new FixedClock());

        var result = await action.ExecuteAsync(new ProcessRemediationTarget { Pid = pid }, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.BlockedCriticalTarget, result.Outcome);
        Assert.Empty(p.Killed);
    }

    [Fact]
    public async Task Kill_Refuses_CurrentProcess()
    {
        var p = WithProcess(999, "DataVanger.exe");
        var action = new KillProcessTreeAction(p, clock: new FixedClock());

        var result = await action.ExecuteAsync(new ProcessRemediationTarget { Pid = 999 }, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.BlockedCriticalTarget, result.Outcome);
        Assert.Empty(p.Killed);
    }

    [Theory]
    [InlineData("lsass.exe")]
    [InlineData("csrss.exe")]
    [InlineData("services.exe")]
    [InlineData("wininit.exe")]
    public async Task Kill_Refuses_CriticalImageNames(string name)
    {
        var p = WithProcess(1500, name);
        var action = new KillProcessTreeAction(p, clock: new FixedClock());

        var result = await action.ExecuteAsync(new ProcessRemediationTarget { Pid = 1500 }, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.BlockedCriticalTarget, result.Outcome);
        Assert.Empty(p.Killed);
    }

    [Fact]
    public async Task Kill_Refuses_UnknownIdentity()
    {
        var p = new FakeProcessProvider(); // PID 1000 not registered
        var action = new KillProcessTreeAction(p, clock: new FixedClock());

        var result = await action.ExecuteAsync(new ProcessRemediationTarget { Pid = 1000 }, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.BlockedUnknownIdentity, result.Outcome);
    }

    [Fact]
    public async Task Kill_Refuses_RecycledPid_NameMismatch()
    {
        var p = WithProcess(1000, "notepad.exe");
        var action = new KillProcessTreeAction(p, clock: new FixedClock());

        var result = await action.ExecuteAsync(
            new ProcessRemediationTarget { Pid = 1000, ExpectedName = "evil.exe" },
            new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.BlockedUnknownIdentity, result.Outcome);
        Assert.Empty(p.Killed);
    }

    [Fact]
    public async Task Kill_Refuses_WholeTree_WhenAnyNodeIsCritical()
    {
        var p = WithProcess(1000, "evil.exe", new[] { 1001 });
        p.Identities[1001] = new ProcessIdentitySnapshot(1001, "lsass.exe", @"C:\Windows\System32\lsass.exe");
        var action = new KillProcessTreeAction(p, clock: new FixedClock());

        var result = await action.ExecuteAsync(new ProcessRemediationTarget { Pid = 1000 }, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.BlockedCriticalTarget, result.Outcome);
        Assert.Empty(p.Killed); // never partially kill
    }

    [Fact]
    public async Task Kill_Refuses_WholeTree_WhenAnyNodeIdentityIsUnknown()
    {
        var p = WithProcess(1000, "evil.exe", new[] { 1001 });
        var action = new KillProcessTreeAction(p, clock: new FixedClock());

        var result = await action.ExecuteAsync(new ProcessRemediationTarget { Pid = 1000 }, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.BlockedUnknownIdentity, result.Outcome);
        Assert.Empty(p.Killed); // never partially kill when a descendant is unknown
    }

    [Fact]
    public async Task Kill_FailureDuringKill_ReportsFailed()
    {
        var p = new FakeProcessProvider { ThrowOnKill = true };
        p.Identities[1000] = new ProcessIdentitySnapshot(1000, "evil.exe", @"C:\Temp\evil.exe");
        var action = new KillProcessTreeAction(p, clock: new FixedClock());

        var result = await action.ExecuteAsync(new ProcessRemediationTarget { Pid = 1000 }, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.Failed, result.Outcome);
    }

    // ── Policy unit ─────────────────────────────────────────────────────────

    [Fact]
    public void CriticalProcessPolicy_FlagsDefaults_AllowsOrdinary()
    {
        var policy = new CriticalProcessPolicy();
        Assert.True(policy.IsCriticalIdentity(new ProcessIdentitySnapshot(1500, "svchost.exe", null)));
        Assert.True(policy.IsCriticalIdentity(new ProcessIdentitySnapshot(1500, "lsass", null)));
        Assert.True(policy.IsCriticalIdentity(new ProcessIdentitySnapshot(1500, "renamed", @"C:\Windows\System32\lsass.exe")));
        Assert.False(policy.IsCriticalIdentity(new ProcessIdentitySnapshot(1500, "evil.exe", null)));
    }

    [Fact]
    public void CriticalProcessPolicy_HonorsAdditionalNames()
    {
        var policy = new CriticalProcessPolicy(new[] { "businessapp.exe" });
        Assert.True(policy.IsCriticalIdentity(new ProcessIdentitySnapshot(1500, "businessapp.exe", null)));
    }
}
