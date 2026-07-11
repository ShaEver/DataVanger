using System;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;
using DataVanger.Core;
using DataVanger.Engine.Updates.SignedUpdates;
using DataVanger.Shared.Updates;

namespace DataVanger.Tests;

// F1 step 1 — the filesystem apply bridge that projects verified update packages into the
// signature root so a signed feed actually updates detection. Network-free: drives the sink's
// IUpdateContentSink contract directly (the SignedUpdateService + verifiers have their own tests)
// and proves SignatureDatabase.Load consumes the projected feed. Filter: ~FileSystemSignatureUpdateSink.
public class FileSystemSignatureUpdateSinkTests
{
    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "dvtest_feedsink_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static void Cleanup(string root)
    {
        try { Directory.Delete(root, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort */ }
    }

    private static StagedPackage HashPkg(string id, UpdatePackageKind kind, params string[] hashes) =>
        new(new UpdatePackageEntry { Id = id, Kind = kind }, Encoding.ASCII.GetBytes(string.Join("\n", hashes) + "\n"));

    private static StagedPackage YaraPkg(string id, string ruleText) =>
        new(new UpdatePackageEntry { Id = id, Kind = UpdatePackageKind.YaraRules }, Encoding.ASCII.GetBytes(ruleText));

    private static readonly string HashA = new string('A', 64);
    private static readonly string HashB = new string('B', 64);
    private static string ActiveRoot(string root) => Assert.Single(SignedFeedProjectionDiscovery.GetVerifiedActiveVersionRoots(root));

    [Fact]
    public void Commit_ProjectsMaliciousFeed_AndSignatureDatabaseReadsIt()
    {
        var root = NewRoot();
        try
        {
            var sink = new FileSystemSignatureUpdateSink(root);
            sink.Stage("feedA", 1, new[] { HashPkg("hb", UpdatePackageKind.HashBlacklist, HashA) });
            sink.Commit("feedA", 1);

            Assert.True(File.Exists(Path.Combine(ActiveRoot(root), FileSystemSignatureUpdateSink.MaliciousFeedFileName)));
            Assert.True(SignatureDatabase.Load(root).IsKnownMalicious(HashA));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void Commit_ProjectsAllowlistFeed_AndSignatureDatabaseReadsIt()
    {
        var root = NewRoot();
        try
        {
            var sink = new FileSystemSignatureUpdateSink(root);
            sink.Stage("feedA", 1, new[] { HashPkg("ha", UpdatePackageKind.HashAllowlist, HashA) });
            sink.Commit("feedA", 1);

            Assert.True(File.Exists(Path.Combine(ActiveRoot(root), FileSystemSignatureUpdateSink.SafeFeedFileName)));
            Assert.True(SignatureDatabase.Load(root).IsKnownSafe(HashA));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void Commit_WritesYaraFeedRule()
    {
        var root = NewRoot();
        try
        {
            const string rule = "rule FeedRule { strings: $a = \"FEEDSTR\" condition: all of them }";
            var sink = new FileSystemSignatureUpdateSink(root);
            sink.Stage("feedA", 1, new[] { YaraPkg("r1", rule) });
            sink.Commit("feedA", 1);

            var yaraFiles = Directory.GetFiles(Path.Combine(ActiveRoot(root), "yara_rules"), FileSystemSignatureUpdateSink.YaraFeedPrefix + "*.yar");
            Assert.Single(yaraFiles);
            Assert.Equal(rule, File.ReadAllText(yaraFiles[0]));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void SecondCommit_ReplacesHashFeed_AndRemovesStaleYara()
    {
        var root = NewRoot();
        try
        {
            var sink = new FileSystemSignatureUpdateSink(root);
            sink.Stage("feedA", 1, new[] { HashPkg("hb", UpdatePackageKind.HashBlacklist, HashA), YaraPkg("r1", "rule R1 {}") });
            sink.Commit("feedA", 1);

            sink.Stage("feedA", 2, new[] { HashPkg("hb", UpdatePackageKind.HashBlacklist, HashB), YaraPkg("r2", "rule R2 {}") });
            sink.Commit("feedA", 2);

            var db = SignatureDatabase.Load(root);
            Assert.True(db.IsKnownMalicious(HashB));
            Assert.False(db.IsKnownMalicious(HashA)); // replaced, not accumulated

            var yaraDir = Path.Combine(ActiveRoot(root), "yara_rules");
            Assert.True(File.Exists(Path.Combine(yaraDir, "feed__r2.yar")));
            Assert.False(File.Exists(Path.Combine(yaraDir, "feed__r1.yar"))); // stale removed
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void Restore_RevertsToLastKnownGood()
    {
        var root = NewRoot();
        try
        {
            var sink = new FileSystemSignatureUpdateSink(root);
            sink.Stage("feedA", 1, new[] { HashPkg("hb", UpdatePackageKind.HashBlacklist, HashA) });
            sink.Commit("feedA", 1);
            sink.Stage("feedA", 2, new[] { HashPkg("hb", UpdatePackageKind.HashBlacklist, HashB) });
            sink.Commit("feedA", 2);

            sink.Restore("feedA");

            var db = SignatureDatabase.Load(root);
            Assert.True(db.IsKnownMalicious(HashA));   // last-known-good restored
            Assert.False(db.IsKnownMalicious(HashB));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void Restart_PreservesActiveAndDurableLastKnownGood_RollbackUsesContent()
    {
        var root = NewRoot();
        try
        {
            var first = new FileSystemSignatureUpdateSink(root);
            first.Stage("feedA", 10, new[] { HashPkg("hb", UpdatePackageKind.HashBlacklist, HashA) });
            first.Commit("feedA", 10);
            first.Stage("feedA", 11, new[] { HashPkg("hb", UpdatePackageKind.HashBlacklist, HashB) });
            first.Commit("feedA", 11);

            var restarted = new FileSystemSignatureUpdateSink(root);
            var health = restarted.GetHealth("feedA");
            Assert.NotNull(health.ActiveVersion);
            Assert.NotNull(health.LastKnownGoodVersion);
            Assert.True(SignatureDatabase.Load(root).IsKnownMalicious(HashB));

            restarted.Restore("feedA");
            Assert.True(SignatureDatabase.Load(root).IsKnownMalicious(HashA));
            Assert.False(SignatureDatabase.Load(root).IsKnownMalicious(HashB));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void TamperedActiveVersion_IsRejectedAsAWhole()
    {
        var root = NewRoot();
        try
        {
            var sink = new FileSystemSignatureUpdateSink(root);
            sink.Stage("feedA", 1, new[] { HashPkg("hb", UpdatePackageKind.HashBlacklist, HashA) });
            sink.Commit("feedA", 1);
            File.AppendAllText(Path.Combine(ActiveRoot(root), FileSystemSignatureUpdateSink.MaliciousFeedFileName), HashB);

            Assert.Empty(SignedFeedProjectionDiscovery.GetVerifiedActiveVersionRoots(root));
            Assert.False(SignatureDatabase.Load(root).IsKnownMalicious(HashA));
            Assert.False(SignatureDatabase.Load(root).IsKnownMalicious(HashB));
        }
        finally { Cleanup(root); }
    }

    [Theory]
    [InlineData(FileSystemSignatureUpdateSink.UpdateFaultPoint.BeforeStageWrite)]
    [InlineData(FileSystemSignatureUpdateSink.UpdateFaultPoint.AfterStageWrite)]
    [InlineData(FileSystemSignatureUpdateSink.UpdateFaultPoint.BeforeVerify)]
    [InlineData(FileSystemSignatureUpdateSink.UpdateFaultPoint.BeforeVersionRename)]
    [InlineData(FileSystemSignatureUpdateSink.UpdateFaultPoint.BeforePointerCommit)]
    [InlineData(FileSystemSignatureUpdateSink.UpdateFaultPoint.AfterPointerCommit)]
    [InlineData(FileSystemSignatureUpdateSink.UpdateFaultPoint.BeforeCleanup)]
    public void InjectedCrashBoundary_RecoversOneCompleteVersion(FileSystemSignatureUpdateSink.UpdateFaultPoint point)
    {
        var root = NewRoot();
        try
        {
            var seed = new FileSystemSignatureUpdateSink(root);
            seed.Stage("feedA", 1, new[] { HashPkg("hb", UpdatePackageKind.HashBlacklist, HashA) });
            seed.Commit("feedA", 1);

            var faulted = new FileSystemSignatureUpdateSink(root, p => { if (p == point) throw new IOException("injected crash boundary"); });
            try
            {
                faulted.Stage("feedA", 2, new[] { HashPkg("hb", UpdatePackageKind.HashBlacklist, HashB) });
                faulted.Commit("feedA", 2);
            }
            catch (IOException) { }

            var restarted = new FileSystemSignatureUpdateSink(root);
            var db = SignatureDatabase.Load(root);
            Assert.True(db.IsKnownMalicious(HashA) ^ db.IsKnownMalicious(HashB));
            Assert.Single(SignedFeedProjectionDiscovery.GetVerifiedActiveVersionRoots(root));
            Assert.False(string.IsNullOrWhiteSpace(restarted.GetHealth("feedA").TransactionState));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void Commit_WithoutMatchingStage_Throws()
    {
        var root = NewRoot();
        try
        {
            var sink = new FileSystemSignatureUpdateSink(root);
            Assert.Throws<InvalidOperationException>(() => sink.Commit("feedA", 99));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void Restore_WithoutLastKnownGood_Throws()
    {
        var root = NewRoot();
        try
        {
            var sink = new FileSystemSignatureUpdateSink(root);
            sink.Stage("feedA", 1, new[] { HashPkg("hb", UpdatePackageKind.HashBlacklist, HashA) });
            sink.Commit("feedA", 1); // only one commit -> no LKG yet
            Assert.Throws<InvalidOperationException>(() => sink.Restore("feedA"));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void Ctor_RejectsBlankRoot()
    {
        Assert.Throws<ArgumentException>(() => new FileSystemSignatureUpdateSink("  "));
    }
}
