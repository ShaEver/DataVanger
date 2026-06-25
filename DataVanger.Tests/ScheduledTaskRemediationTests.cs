using System;
using System.Collections.Generic;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Rollback;
using DataVanger.Engine.Remediation.SystemScope;
using Xunit;

// Phase 03C — scheduled task remediation tests (fake provider only).
public class ScheduledTaskRemediationTests
{
    private sealed class FixedClock : IRemediationClock
    {
        public DateTimeOffset UtcNow { get; set; } = new(2026, 6, 13, 0, 0, 0, TimeSpan.Zero);
    }

    private sealed class FakeTaskProvider : IScheduledTaskRemediationProvider
    {
        public Dictionary<string, string> Tasks { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Deleted { get; } = new();
        public List<ScheduledTaskXmlExport> Imported { get; } = new();
        public bool ExportFails { get; init; }

        public bool Exists(string taskPath) => Tasks.ContainsKey(taskPath);

        public ScheduledTaskXmlExport? ExportXml(string taskPath)
        {
            if (ExportFails) return null;
            return Tasks.TryGetValue(taskPath, out var xml) ? new ScheduledTaskXmlExport(taskPath, xml) : null;
        }

        public void Delete(string taskPath) { Tasks.Remove(taskPath); Deleted.Add(taskPath); }
        public void Import(ScheduledTaskXmlExport export) { Imported.Add(export); Tasks[export.TaskPath] = export.Xml; }
    }

    private static ScheduledTaskTarget Target() => new() { TaskPath = @"\Microsoft\Windows\EvilTask" };

    [Fact]
    public async Task Remove_ExportsXmlBeforeDelete_ProducesRollback()
    {
        var p = new FakeTaskProvider();
        p.Tasks[@"\Microsoft\Windows\EvilTask"] = "<Task><Actions>evil</Actions></Task>";
        var action = new RemoveScheduledTaskAction(p, new FixedClock());
        var journal = new InMemoryRemediationJournal();

        var result = await action.ExecuteAsync(Target(), journal, RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.Succeeded, result.Outcome);
        Assert.Single(p.Deleted);
        Assert.Equal(RollbackTokenKind.ScheduledTaskExport, result.RollbackToken!.Kind);
        Assert.Contains("TaskPath", result.RollbackToken.Payload);
        Assert.Contains("Xml", result.RollbackToken.Payload);
        // Intent journaled before the delete.
        Assert.Equal(RemediationJournalEntryKind.Intent, journal.ForCorrelation(result.RollbackToken.CorrelationId)[0].EntryKind);
    }

    [Fact]
    public async Task Remove_BlocksDelete_WhenExportFails()
    {
        var p = new FakeTaskProvider { ExportFails = true };
        p.Tasks[@"\Microsoft\Windows\EvilTask"] = "<Task/>";
        var action = new RemoveScheduledTaskAction(p, new FixedClock());

        var result = await action.ExecuteAsync(Target(), new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.BlockedExportFailed, result.Outcome);
        Assert.Empty(p.Deleted); // never delete without a successful export
    }

    [Fact]
    public async Task Remove_RefusesMissingTask()
    {
        var p = new FakeTaskProvider();
        var action = new RemoveScheduledTaskAction(p, new FixedClock());

        var result = await action.ExecuteAsync(Target(), new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.BlockedTargetNotFound, result.Outcome);
    }

    [Fact]
    public async Task Rollback_ReimportsExportedXml()
    {
        var p = new FakeTaskProvider();
        p.Tasks[@"\Microsoft\Windows\EvilTask"] = "<Task>x</Task>";
        var action = new RemoveScheduledTaskAction(p, new FixedClock());

        var removed = await action.ExecuteAsync(Target(), new InMemoryRemediationJournal(), RemediationCorrelationId.New());
        Assert.Equal(SystemRemediationOutcome.Succeeded, removed.Outcome);
        Assert.False(p.Exists(@"\Microsoft\Windows\EvilTask"));

        var rollback = action.Rollback(removed.RollbackToken!);

        Assert.Equal(SystemRemediationOutcome.RolledBack, rollback.Outcome);
        Assert.True(p.Exists(@"\Microsoft\Windows\EvilTask"));
        Assert.Contains(p.Imported, export => export.TaskPath == @"\Microsoft\Windows\EvilTask" && export.Xml == "<Task>x</Task>");
    }
}
