using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Rollback;

namespace DataVanger.Engine.Remediation.SystemScope;

/// <summary>An autorun/persistence registry value to remove. Identified by hive,
/// key path, and value name.</summary>
public sealed record RegistryAutorunTarget
{
    public required string Hive { get; init; }      // e.g. HKLM, HKCU
    public required string KeyPath { get; init; }   // e.g. SOFTWARE\...\Run
    public required string ValueName { get; init; }

    /// <summary>The value DATA captured when the plan was built. Removal refuses
    /// if the live value differs (changed-since-plan).</summary>
    public string? ExpectedData { get; init; }
}

/// <summary>An exact, complete snapshot of a registry value for backup/rollback.</summary>
public sealed record RegistryValueBackup(string Hive, string KeyPath, string ValueName, string ValueType, string Data);

/// <summary>OS seam for registry remediation.</summary>
public interface IRegistryRemediationProvider
{
    /// <summary>Reads the exact current value (type + data), or null if absent.</summary>
    RegistryValueBackup? ReadValue(string hive, string keyPath, string valueName);

    void DeleteValue(string hive, string keyPath, string valueName);

    /// <summary>Re-creates a backed-up value exactly (hive/key/name/type/data).</summary>
    void RestoreValue(RegistryValueBackup backup);
}

/// <summary>
/// Removes a malicious autorun registry value. Requires an exact value backup
/// (hive/key/name/type/data) BEFORE deletion, refuses when the live value differs
/// from the planned data (changed-since-plan), and produces a RegistryValueBackup
/// rollback token. Journaled before mutation.
/// </summary>
public sealed class RemoveRegistryAutorunAction
{
    private readonly IRegistryRemediationProvider _provider;
    private readonly IRemediationClock _clock;

    public RemoveRegistryAutorunAction(IRegistryRemediationProvider provider, IRemediationClock? clock = null)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _clock = clock ?? SystemRemediationClock.Instance;
    }

    public Task<SystemRemediationResult> ExecuteAsync(
        RegistryAutorunTarget target,
        IRemediationJournal journal,
        RemediationCorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (target is null) throw new ArgumentNullException(nameof(target));
        if (journal is null) throw new ArgumentNullException(nameof(journal));

        var matchKey = $"RegistryValue:{target.Hive}\\{target.KeyPath}\\{target.ValueName}".ToLowerInvariant();

        var backup = _provider.ReadValue(target.Hive, target.KeyPath, target.ValueName);
        if (backup is null)
            return Block(SystemRemediationOutcome.BlockedTargetNotFound, "Registry value does not exist.");

        // Changed-since-plan: if the plan captured an expected value, the live data
        // must still match it, otherwise refuse and require a replan.
        if (target.ExpectedData is not null &&
            !string.Equals(target.ExpectedData, backup.Data, StringComparison.Ordinal))
            return Block(SystemRemediationOutcome.BlockedChangedSincePlan, "Registry value changed since the plan was built; refusing to delete a value that is not what was planned. Replan required.");

        var backupRef = SerializeBackup(backup);
        SystemRemediationJournal.Intent(journal, correlationId, RemediationActionKind.RemoveRegistryAutorun, matchKey, _clock,
            RollbackTokenKind.RegistryValueBackup, backupRef);

        try
        {
            _provider.DeleteValue(target.Hive, target.KeyPath, target.ValueName);
        }
        catch (Exception ex)
        {
            SystemRemediationJournal.Outcome(journal, correlationId, RemediationActionKind.RemoveRegistryAutorun, matchKey, _clock, $"Failed: {ex.GetType().Name}");
            return Task.FromResult(new SystemRemediationResult
            {
                Outcome = SystemRemediationOutcome.Failed,
                Reason = $"Registry delete failed: {ex.GetType().Name}: {ex.Message}. Exact value captured for rollback.",
                TargetId = matchKey,
                BackupRef = backupRef,
                RollbackToken = RollbackToken.For(RollbackTokenKind.RegistryValueBackup, backupRef, correlationId),
            });
        }

        SystemRemediationJournal.Outcome(journal, correlationId, RemediationActionKind.RemoveRegistryAutorun, matchKey, _clock, "Succeeded", RollbackTokenKind.RegistryValueBackup);

        return Task.FromResult(new SystemRemediationResult
        {
            Outcome = SystemRemediationOutcome.Succeeded,
            Reason = "Autorun value removed; exact value backed up for rollback.",
            TargetId = matchKey,
            BackupRef = backupRef,
            RollbackToken = RollbackToken.For(RollbackTokenKind.RegistryValueBackup, backupRef, correlationId),
        });
    }

    /// <summary>Restores a previously backed-up registry value exactly.</summary>
    public SystemRemediationResult Rollback(RegistryValueBackup backup)
    {
        try
        {
            _provider.RestoreValue(backup);
            return new SystemRemediationResult { Outcome = SystemRemediationOutcome.RolledBack, Reason = "Registry value restored." };
        }
        catch (Exception ex)
        {
            return new SystemRemediationResult { Outcome = SystemRemediationOutcome.RollbackFailed, Reason = $"Rollback failed: {ex.GetType().Name}: {ex.Message}" };
        }
    }

    /// <summary>Restores a registry value from a self-contained RegistryValueBackup token.</summary>
    public SystemRemediationResult Rollback(RollbackToken token)
    {
        if (token is null) throw new ArgumentNullException(nameof(token));
        if (token.Kind != RollbackTokenKind.RegistryValueBackup || string.IsNullOrWhiteSpace(token.Payload))
            return new SystemRemediationResult { Outcome = SystemRemediationOutcome.RollbackFailed, Reason = "Rollback token is not a registry-value backup token." };

        try
        {
            var backup = JsonSerializer.Deserialize<RegistryValueBackup>(token.Payload);
            return backup is null
                ? new SystemRemediationResult { Outcome = SystemRemediationOutcome.RollbackFailed, Reason = "Registry rollback token payload could not be decoded." }
                : Rollback(backup);
        }
        catch (JsonException ex)
        {
            return new SystemRemediationResult { Outcome = SystemRemediationOutcome.RollbackFailed, Reason = $"Registry rollback token payload is invalid: {ex.Message}" };
        }
    }

    internal static string SerializeBackup(RegistryValueBackup b)
        => JsonSerializer.Serialize(b);

    private static Task<SystemRemediationResult> Block(SystemRemediationOutcome outcome, string reason)
        => Task.FromResult(new SystemRemediationResult { Outcome = outcome, Reason = reason });
}
