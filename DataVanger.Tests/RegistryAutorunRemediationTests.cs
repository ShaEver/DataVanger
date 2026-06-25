using System;
using System.Collections.Generic;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Rollback;
using DataVanger.Engine.Remediation.SystemScope;
using Xunit;

// Phase 03C — registry autorun remediation tests (fake provider only).
public class RegistryAutorunRemediationTests
{
    private sealed class FixedClock : IRemediationClock
    {
        public DateTimeOffset UtcNow { get; set; } = new(2026, 6, 13, 0, 0, 0, TimeSpan.Zero);
    }

    private sealed class FakeRegistryProvider : IRegistryRemediationProvider
    {
        private readonly Dictionary<string, RegistryValueBackup> _values = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Deleted { get; } = new();
        public List<RegistryValueBackup> Restored { get; } = new();
        public bool ThrowOnDelete { get; init; }

        private static string Key(string hive, string keyPath, string name) => $"{hive}|{keyPath}|{name}";

        public void Seed(RegistryValueBackup v) => _values[Key(v.Hive, v.KeyPath, v.ValueName)] = v;

        public RegistryValueBackup? ReadValue(string hive, string keyPath, string valueName)
            => _values.TryGetValue(Key(hive, keyPath, valueName), out var v) ? v : null;

        public void DeleteValue(string hive, string keyPath, string valueName)
        {
            if (ThrowOnDelete) throw new InvalidOperationException("simulated registry delete failure");
            _values.Remove(Key(hive, keyPath, valueName));
            Deleted.Add(Key(hive, keyPath, valueName));
        }

        public void RestoreValue(RegistryValueBackup backup)
        {
            Restored.Add(backup);
            Seed(backup);
        }
    }

    private static RegistryAutorunTarget Target(string? expectedData = null) => new()
    {
        Hive = "HKCU",
        KeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ValueName = "EvilApp",
        ExpectedData = expectedData,
    };

    [Fact]
    public async Task Remove_BacksUpExactValue_BeforeDeleting_ProducesRollback()
    {
        var p = new FakeRegistryProvider();
        p.Seed(new RegistryValueBackup("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "EvilApp", "REG_SZ", @"C:\Temp\evil.exe"));
        var action = new RemoveRegistryAutorunAction(p, new FixedClock());
        var journal = new InMemoryRemediationJournal();

        var result = await action.ExecuteAsync(Target(@"C:\Temp\evil.exe"), journal, RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.Succeeded, result.Outcome);
        Assert.Single(p.Deleted);
        Assert.Equal(RollbackTokenKind.RegistryValueBackup, result.RollbackToken!.Kind);
        // The backup ref carries hive/key/name/type/data.
        Assert.Contains("REG_SZ", result.BackupRef);
        Assert.Contains("evil.exe", result.BackupRef);
        // Intent journaled before outcome.
        var records = journal.ForCorrelation(result.RollbackToken.CorrelationId);
        Assert.Equal(RemediationJournalEntryKind.Intent, records[0].EntryKind);
    }

    [Fact]
    public async Task Remove_RefusesWhenValueChangedSincePlan()
    {
        var p = new FakeRegistryProvider();
        p.Seed(new RegistryValueBackup("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "EvilApp", "REG_SZ", @"C:\Temp\NEW-value.exe"));
        var action = new RemoveRegistryAutorunAction(p, new FixedClock());

        // Plan expected the OLD value; the live value differs.
        var result = await action.ExecuteAsync(Target(@"C:\Temp\evil.exe"), new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.BlockedChangedSincePlan, result.Outcome);
        Assert.Empty(p.Deleted);
    }

    [Fact]
    public async Task Remove_RefusesMissingValue()
    {
        var p = new FakeRegistryProvider(); // nothing seeded
        var action = new RemoveRegistryAutorunAction(p, new FixedClock());

        var result = await action.ExecuteAsync(Target(), new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.BlockedTargetNotFound, result.Outcome);
    }

    [Fact]
    public async Task Remove_FailureKeepsBackupForRollback()
    {
        var p = new FakeRegistryProvider { ThrowOnDelete = true };
        p.Seed(new RegistryValueBackup("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "EvilApp", "REG_SZ", @"C:\Temp\evil.exe"));
        var action = new RemoveRegistryAutorunAction(p, new FixedClock());

        var result = await action.ExecuteAsync(Target(), new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.Failed, result.Outcome);
        Assert.NotNull(result.RollbackToken);
    }

    [Fact]
    public async Task Remove_RollbackToken_IsSelfContained_ForExactValue()
    {
        var p = new FakeRegistryProvider();
        p.Seed(new RegistryValueBackup("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Evil|App", "REG_SZ", @"C:\Temp\evil|payload.exe"));
        var action = new RemoveRegistryAutorunAction(p, new FixedClock());

        var removed = await action.ExecuteAsync(new RegistryAutorunTarget
        {
            Hive = "HKCU",
            KeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            ValueName = "Evil|App",
            ExpectedData = @"C:\Temp\evil|payload.exe",
        }, new InMemoryRemediationJournal(), RemediationCorrelationId.New());
        var rollback = action.Rollback(removed.RollbackToken!);

        Assert.Equal(SystemRemediationOutcome.RolledBack, rollback.Outcome);
        Assert.NotNull(p.ReadValue("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Evil|App"));
        Assert.Contains(p.Restored, backup => backup.Data == @"C:\Temp\evil|payload.exe");
    }

    [Fact]
    public async Task Rollback_RestoresExactValue()
    {
        var p = new FakeRegistryProvider();
        p.Seed(new RegistryValueBackup("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "EvilApp", "REG_SZ", @"C:\Temp\evil.exe"));
        var action = new RemoveRegistryAutorunAction(p, new FixedClock());

        var removed = await action.ExecuteAsync(Target(), new InMemoryRemediationJournal(), RemediationCorrelationId.New());
        Assert.Equal(SystemRemediationOutcome.Succeeded, removed.Outcome);

        var backup = new RegistryValueBackup("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "EvilApp", "REG_SZ", @"C:\Temp\evil.exe");
        var rollback = action.Rollback(backup);

        Assert.Equal(SystemRemediationOutcome.RolledBack, rollback.Outcome);
        Assert.Single(p.Restored);
        Assert.NotNull(p.ReadValue("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "EvilApp"));
    }
}
