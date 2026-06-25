using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Remediation.Files;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Engine.Remediation.SystemScope;

/// <summary>A startup-folder item to remove. The LINK/file itself is what gets
/// quarantined and removed; the optional target path is recorded separately for
/// audit and is NEVER deleted by this action.</summary>
public sealed record StartupFolderItemTarget
{
    public required string LinkPath { get; init; }
    public string? TargetPath { get; init; }
    public QuarantineThreatClassification Classification { get; init; } = QuarantineThreatClassification.ConfirmedMalware;
}

/// <summary>
/// Removes a malicious startup-folder item by QUARANTINING the link/file first
/// (via the 03B file remediation service) and only then removing it. If quarantine
/// fails, the item is left untouched. The link's target (if any) is recorded but
/// never deleted here — that is a separate file action. The rollback token is the
/// quarantine-restore token from the file service.
/// </summary>
public sealed class RemoveStartupFolderItemAction
{
    private readonly FileRemediationService _fileRemediation;

    public RemoveStartupFolderItemAction(FileRemediationService fileRemediation)
        => _fileRemediation = fileRemediation ?? throw new ArgumentNullException(nameof(fileRemediation));

    public async Task<SystemRemediationResult> ExecuteAsync(
        StartupFolderItemTarget target,
        IRemediationJournal journal,
        RemediationCorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (target is null) throw new ArgumentNullException(nameof(target));
        if (journal is null) throw new ArgumentNullException(nameof(journal));

        var matchKey = $"StartupEntry:{target.LinkPath.ToLowerInvariant()}";

        var fileResult = await _fileRemediation.QuarantineAndDeleteAsync(new FileRemediationRequest
        {
            OriginalPath = target.LinkPath,
            Classification = target.Classification,
            Origin = QuarantineRequestOrigin.ManualUserApproved,
            DetectionSummary = "Startup folder persistence item",
            SourceModule = "StartupFolderRemediation",
        }, journal, correlationId, cancellationToken).ConfigureAwait(false);

        // Quarantine must precede removal. Any non-deletion outcome means the link
        // was NOT removed (quarantine failed / unsafe / hash mismatch).
        if (fileResult.Outcome != FileRemediationOutcome.OriginalDeleted)
        {
            return new SystemRemediationResult
            {
                Outcome = SystemRemediationOutcome.BlockedQuarantineFailed,
                Reason = $"Startup item not removed: {fileResult.Outcome} — {fileResult.Reason}",
                TargetId = matchKey,
            };
        }

        return new SystemRemediationResult
        {
            Outcome = SystemRemediationOutcome.Succeeded,
            Reason = "Startup item quarantined and removed; link target recorded separately (not deleted).",
            TargetId = matchKey,
            RollbackToken = fileResult.RollbackToken,
            BackupRef = target.TargetPath is null ? null : $"linkTarget:{target.TargetPath}",
        };
    }
}
