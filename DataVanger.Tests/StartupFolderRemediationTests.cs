using System;
using System.IO;
using DataVanger.Engine.Quarantine;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Files;
using DataVanger.Engine.Remediation.Journal;
using DataVanger.Engine.Remediation.Rollback;
using DataVanger.Engine.Remediation.SystemScope;
using DataVanger.Shared.Quarantine;
using Xunit;

// Phase 03C — startup-folder item remediation tests. Proves quarantine-before-
// removal by composing the real 03B FileRemediationService over in-memory
// quarantine + temp files.
public class StartupFolderRemediationTests : IDisposable
{
    private readonly string _tempDir;

    public StartupFolderRemediationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "dv-startup-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch (IOException) { /* best-effort */ }
        catch (UnauthorizedAccessException) { /* best-effort */ }
    }

    private static FileRemediationService BuildFileService()
    {
        var store = new InMemoryQuarantineStore();
        var service = new QuarantineService(
            store, new QuarantineCryptoProvider(), new InMemoryQuarantineKeyProtector("startup-seed"), new QuarantineOptions());
        return new FileRemediationService(
            new QuarantineServiceRemediationGateway(service),
            new QuarantineStoreCleanup(store),
            new Sha256FileHashProvider(),
            new RemediationSafePathPolicy(),
            new SystemFileRemediationOperations());
    }

    [Fact]
    public async Task Remove_QuarantinesLinkBeforeDeleting_ProducesRollback()
    {
        var link = Path.Combine(_tempDir, "evil.lnk");
        File.WriteAllText(link, "shortcut-bytes");
        var fileService = BuildFileService();
        var action = new RemoveStartupFolderItemAction(fileService);
        var journal = new InMemoryRemediationJournal();

        var result = await action.ExecuteAsync(
            new StartupFolderItemTarget { LinkPath = link, TargetPath = @"C:\Temp\evil.exe" },
            journal, RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.Succeeded, result.Outcome);
        Assert.False(File.Exists(link), "Startup link must be removed after quarantine.");
        Assert.Equal(RollbackTokenKind.QuarantineRestore, result.RollbackToken!.Kind);
        // The link target is recorded but never deleted.
        Assert.Contains("evil.exe", result.BackupRef);

        var restore = await fileService.RestoreAsync(result.RollbackToken);
        Assert.Equal(FileRemediationOutcome.Restored, restore.Outcome);
        Assert.True(File.Exists(link), "Startup link rollback should restore through the 03B quarantine token.");
    }

    [Fact]
    public async Task Remove_BlockedWhenQuarantineFails_LeavesItemUntouched()
    {
        // A non-existent link makes quarantine fail (BlockedSourceMissing); the
        // startup action must then leave the item untouched and not "succeed".
        var link = Path.Combine(_tempDir, "ghost.lnk");
        var action = new RemoveStartupFolderItemAction(BuildFileService());

        var result = await action.ExecuteAsync(
            new StartupFolderItemTarget { LinkPath = link },
            new InMemoryRemediationJournal(), RemediationCorrelationId.New());

        Assert.Equal(SystemRemediationOutcome.BlockedQuarantineFailed, result.Outcome);
    }
}
