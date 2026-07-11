using System;
using System.Collections.Generic;
using System.Threading;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Rollback;
using DataVanger.Engine.Remediation.SystemScope;
using Xunit;

// Phase 03C — service remediation tests (fake provider only).
public class ServiceRemediationTests
{
    private sealed class FixedClock : IRemediationClock
    {
        public DateTimeOffset UtcNow { get; set; } = new(2026, 6, 13, 0, 0, 0, TimeSpan.Zero);
    }

    private sealed class FakeServiceProvider : IServiceRemediationProvider
    {
        public Dictionary<string, ServiceStateBackup> Services { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Stopped { get; } = new();
        public List<string> Disabled { get; } = new();
        public List<ServiceStateBackup> Restored { get; } = new();
        public bool ThrowOnStop { get; init; }

        public ServiceStateBackup? ReadState(string serviceName)
            => Services.TryGetValue(serviceName, out var s) ? s : null;

        public void Stop(string serviceName)
        {
            if (ThrowOnStop) throw new InvalidOperationException("simulated stop failure");
            Stopped.Add(serviceName);
        }

        public void Disable(string serviceName) => Disabled.Add(serviceName);
        public void Restore(ServiceStateBackup backup) => Restored.Add(backup);
    }

    [Fact]
    public async Task StopDisable_NonCritical_BacksUpStartType_ProducesRollback()
    {
        var p = new FakeServiceProvider();
        p.Services["EvilSvc"] = new ServiceStateBackup("EvilSvc", "auto", WasRunning: true);
        var action = new StopDisableServiceAction(p, clock: new FixedClock());
        var journal = new InMemoryRemediationJournal();

        var result = await action.ExecuteAsync(new ServiceRemediationTarget { ServiceName = "EvilSvc" }, journal, RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.Succeeded, result.Outcome);
        Assert.Contains("EvilSvc", p.Stopped);
        Assert.Contains("EvilSvc", p.Disabled);
        Assert.Equal(RollbackTokenKind.ServiceConfigBackup, result.RollbackToken!.Kind);
        Assert.True(result.RollbackToken.CanRollback);
        // Journal intent carries the backup before-state.
        var intent = journal.ForCorrelation(result.RollbackToken.CorrelationId)[0];
        Assert.Contains("start=auto", intent.BeforeStateRef);
    }

    [Theory]
    [InlineData("wininit")]
    [InlineData("rpcss")]
    [InlineData("RpcEptMapper")]
    [InlineData("Winmgmt")]
    [InlineData("windefend")]
    [InlineData("WdNisSvc")]
    [InlineData("Sense")]
    [InlineData("lsass")]
    public async Task StopDisable_RefusesCriticalServices(string name)
    {
        var p = new FakeServiceProvider();
        p.Services[name] = new ServiceStateBackup(name, "auto", true);
        var action = new StopDisableServiceAction(p, clock: new FixedClock());

        var result = await action.ExecuteAsync(new ServiceRemediationTarget { ServiceName = name }, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.BlockedCriticalTarget, result.Outcome);
        Assert.Empty(p.Stopped);
        Assert.Empty(p.Disabled);
    }

    [Fact]
    public async Task StopDisable_RefusesMissingService()
    {
        var p = new FakeServiceProvider(); // no service registered
        var action = new StopDisableServiceAction(p, clock: new FixedClock());

        var result = await action.ExecuteAsync(new ServiceRemediationTarget { ServiceName = "Ghost" }, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.BlockedTargetNotFound, result.Outcome);
    }

    [Fact]
    public async Task StopDisable_FailureKeepsRollbackToken()
    {
        var p = new FakeServiceProvider { ThrowOnStop = true };
        p.Services["EvilSvc"] = new ServiceStateBackup("EvilSvc", "auto", true);
        var action = new StopDisableServiceAction(p, clock: new FixedClock());

        var result = await action.ExecuteAsync(new ServiceRemediationTarget { ServiceName = "EvilSvc" }, new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.Failed, result.Outcome);
        Assert.NotNull(result.RollbackToken);
    }

    [Fact]
    public async Task StopDisable_RollbackToken_IsSelfContained()
    {
        var p = new FakeServiceProvider();
        p.Services["EvilSvc"] = new ServiceStateBackup("EvilSvc", "auto|delayed", WasRunning: true);
        var action = new StopDisableServiceAction(p, clock: new FixedClock());

        var removed = await action.ExecuteAsync(new ServiceRemediationTarget { ServiceName = "EvilSvc" }, new InMemoryRemediationJournal(), RemediationCorrelationId.New());
        var rollback = action.Rollback(removed.RollbackToken!);

        Assert.Equal(SystemRemediationOutcome.RolledBack, rollback.Outcome);
        Assert.Contains(p.Restored, backup => backup.ServiceName == "EvilSvc" && backup.StartType == "auto|delayed" && backup.WasRunning);
    }

    [Fact]
    public void Rollback_RestoresStartType()
    {
        var p = new FakeServiceProvider();
        var action = new StopDisableServiceAction(p, clock: new FixedClock());
        var backup = new ServiceStateBackup("EvilSvc", "auto", true);

        var result = action.Rollback(backup);

        Assert.Equal(SystemRemediationOutcome.RolledBack, result.Outcome);
        Assert.Single(p.Restored);
    }

    [Fact]
    public void CriticalServicePolicy_RefusesBlankName()
        => Assert.True(new CriticalServicePolicy().IsCritical("   "));
}
