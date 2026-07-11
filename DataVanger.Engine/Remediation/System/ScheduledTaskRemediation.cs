using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Rollback;

namespace DataVanger.Engine.Remediation.SystemScope;

/// <summary>A scheduled task to remove, identified by its full task path/name.</summary>
public sealed record ScheduledTaskTarget
{
    public required string TaskPath { get; init; }
}

/// <summary>The exported XML definition of a scheduled task, captured before
/// deletion so the task can be re-imported on rollback.</summary>
public sealed record ScheduledTaskXmlExport(string TaskPath, string Xml);

/// <summary>OS seam for scheduled-task remediation.</summary>
public interface IScheduledTaskRemediationProvider
{
    bool Exists(string taskPath);

    /// <summary>Exports the task definition XML, or null if export fails/the task is
    /// absent. A null export MUST block deletion.</summary>
    ScheduledTaskXmlExport? ExportXml(string taskPath);

    void Delete(string taskPath);

    /// <summary>Re-imports a previously exported task definition.</summary>
    void Import(ScheduledTaskXmlExport export);
}

/// <summary>
/// Removes a malicious scheduled task. The task's XML is exported BEFORE deletion;
/// if export fails, the task is NOT deleted (irreversible-loss protection). A
/// successful export becomes the ScheduledTaskExport rollback token. Journaled
/// before mutation.
/// </summary>
public sealed class RemoveScheduledTaskAction
{
    private readonly IScheduledTaskRemediationProvider _provider;
    private readonly IRemediationClock _clock;

    public RemoveScheduledTaskAction(IScheduledTaskRemediationProvider provider, IRemediationClock? clock = null)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _clock = clock ?? SystemRemediationClock.Instance;
    }

    public Task<SystemRemediationResult> ExecuteAsync(
        ScheduledTaskTarget target,
        IRemediationJournal journal,
        RemediationCorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (target is null) throw new ArgumentNullException(nameof(target));
        if (journal is null) throw new ArgumentNullException(nameof(journal));

        var matchKey = $"ScheduledTask:{target.TaskPath.ToLowerInvariant()}";

        if (!_provider.Exists(target.TaskPath))
            return Block(SystemRemediationOutcome.BlockedTargetNotFound, $"Scheduled task '{target.TaskPath}' does not exist.");

        // Export-before-delete: a failed/empty export blocks deletion outright.
        var export = _provider.ExportXml(target.TaskPath);
        if (export is null || string.IsNullOrWhiteSpace(export.Xml))
            return Block(SystemRemediationOutcome.BlockedExportFailed, "Scheduled task XML export failed; refusing to delete a task that cannot be restored.");

        var backupRef = $"xml:{export.Xml.Length}bytes";
        SystemRemediationJournal.Intent(journal, correlationId, RemediationActionKind.RemoveScheduledTask, matchKey, _clock,
            RollbackTokenKind.ScheduledTaskExport, backupRef);

        try
        {
            _provider.Delete(target.TaskPath);
        }
        catch (Exception ex)
        {
            SystemRemediationJournal.Outcome(journal, correlationId, RemediationActionKind.RemoveScheduledTask, matchKey, _clock, $"Failed: {ex.GetType().Name}");
            return Task.FromResult(new SystemRemediationResult
            {
                Outcome = SystemRemediationOutcome.Failed,
                Reason = $"Task delete failed: {ex.GetType().Name}: {ex.Message}. XML exported for rollback.",
                TargetId = matchKey,
                BackupRef = backupRef,
                RollbackToken = RollbackToken.For(RollbackTokenKind.ScheduledTaskExport, SerializeExport(export), correlationId),
            });
        }

        SystemRemediationJournal.Outcome(journal, correlationId, RemediationActionKind.RemoveScheduledTask, matchKey, _clock, "Succeeded", RollbackTokenKind.ScheduledTaskExport);

        return Task.FromResult(new SystemRemediationResult
        {
            Outcome = SystemRemediationOutcome.Succeeded,
            Reason = "Scheduled task removed after XML export; export retained for rollback.",
            TargetId = matchKey,
            BackupRef = backupRef,
            RollbackToken = RollbackToken.For(RollbackTokenKind.ScheduledTaskExport, SerializeExport(export), correlationId),
        });
    }

    /// <summary>Re-imports a previously exported task definition.</summary>
    public SystemRemediationResult Rollback(ScheduledTaskXmlExport export)
    {
        try
        {
            _provider.Import(export);
            return new SystemRemediationResult { Outcome = SystemRemediationOutcome.RolledBack, Reason = "Scheduled task re-imported." };
        }
        catch (Exception ex)
        {
            return new SystemRemediationResult { Outcome = SystemRemediationOutcome.RollbackFailed, Reason = $"Rollback failed: {ex.GetType().Name}: {ex.Message}" };
        }
    }

    /// <summary>Re-imports a scheduled task from a self-contained ScheduledTaskExport token.</summary>
    public SystemRemediationResult Rollback(RollbackToken token)
    {
        if (token is null) throw new ArgumentNullException(nameof(token));
        if (token.Kind != RollbackTokenKind.ScheduledTaskExport || string.IsNullOrWhiteSpace(token.Payload))
            return new SystemRemediationResult { Outcome = SystemRemediationOutcome.RollbackFailed, Reason = "Rollback token is not a scheduled-task export token." };

        try
        {
            var export = JsonSerializer.Deserialize<ScheduledTaskXmlExport>(token.Payload);
            return export is null || string.IsNullOrWhiteSpace(export.TaskPath) || string.IsNullOrWhiteSpace(export.Xml)
                ? new SystemRemediationResult { Outcome = SystemRemediationOutcome.RollbackFailed, Reason = "Scheduled-task rollback token payload could not be decoded." }
                : Rollback(export);
        }
        catch (JsonException ex)
        {
            return new SystemRemediationResult { Outcome = SystemRemediationOutcome.RollbackFailed, Reason = $"Scheduled-task rollback token payload is invalid: {ex.Message}" };
        }
    }

    internal static string SerializeExport(ScheduledTaskXmlExport export)
        => JsonSerializer.Serialize(export);

    private static Task<SystemRemediationResult> Block(SystemRemediationOutcome outcome, string reason)
        => Task.FromResult(new SystemRemediationResult { Outcome = outcome, Reason = reason });
}
