using System;
using System.IO;
using System.Linq;
using Xunit;
using DataVanger.Core;

namespace DataVanger.Tests;

// Junk cleaner efficiency/safety improvements:
//  - Measurement uses the cheap candidate gate (no exclusive open per file);
//  - the lock test is a separate delete-time concern;
//  - pre-delete backups are bounded by a retention policy.
// Filter: ~JunkCleaner.
public class JunkCleanerTests
{
    private static string NewDir()
    {
        var root = Path.Combine(Path.GetTempPath(), "dvtest_junk_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static void Cleanup(string root)
    {
        try { Directory.Delete(root, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort */ }
    }

    [Fact]
    public void IsCleanableCandidate_TrueForOldSafeExtension()
    {
        var dir = NewDir();
        try
        {
            var file = Path.Combine(dir, "stale.tmp");
            File.WriteAllText(file, "junk");
            File.SetLastWriteTime(file, DateTime.Now.AddMinutes(-10));
            var loc = new JunkLocation { Path = dir, MinimumAge = TimeSpan.Zero };

            Assert.True(JunkCleaningPolicy.IsCleanableCandidate(file, loc));
        }
        finally { Cleanup(dir); }
    }

    [Fact]
    public void IsCleanableCandidate_RequiresNoFileAccess_EvenWhenLocked()
    {
        // The whole point of the split: the measurement pass must classify a file without
        // opening it, so a file exclusively held by another handle is still measured.
        var dir = NewDir();
        try
        {
            var file = Path.Combine(dir, "locked.tmp");
            File.WriteAllText(file, "junk");
            File.SetLastWriteTime(file, DateTime.Now.AddMinutes(-10));
            var loc = new JunkLocation { Path = dir, MinimumAge = TimeSpan.Zero };

            using var hold = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

            Assert.True(JunkCleaningPolicy.IsCleanableCandidate(file, loc));   // no open needed
            Assert.False(JunkCleaningPolicy.IsDeletableNow(file));             // but it is locked now
            Assert.False(JunkCleaningPolicy.IsCleanableFile(file, loc, out bool inUse));
            Assert.True(inUse);                                               // combined check flags in-use
        }
        finally { Cleanup(dir); }
    }

    [Fact]
    public void IsDeletableNow_TrueWhenUnlocked()
    {
        var dir = NewDir();
        try
        {
            var file = Path.Combine(dir, "free.tmp");
            File.WriteAllText(file, "junk");
            Assert.True(JunkCleaningPolicy.IsDeletableNow(file));
        }
        finally { Cleanup(dir); }
    }

    [Fact]
    public void IsCleanableCandidate_FalseForExecutableInstaller()
    {
        var dir = NewDir();
        try
        {
            var file = Path.Combine(dir, "setup.exe");
            File.WriteAllText(file, "MZ");
            var loc = new JunkLocation { Path = dir, MinimumAge = TimeSpan.Zero, IncludeExecutableInstallers = false };
            Assert.False(JunkCleaningPolicy.IsCleanableCandidate(file, loc));
        }
        finally { Cleanup(dir); }
    }

    [Fact]
    public void IsCleanableCandidate_FalseForRecentFile()
    {
        var dir = NewDir();
        try
        {
            var file = Path.Combine(dir, "fresh.tmp");
            File.WriteAllText(file, "junk");
            var loc = new JunkLocation { Path = dir, MinimumAge = TimeSpan.FromDays(7) }; // file is brand new
            Assert.False(JunkCleaningPolicy.IsCleanableCandidate(file, loc));
        }
        finally { Cleanup(dir); }
    }

    [Fact]
    public void PruneOldBackups_KeepsOnlyMostRecent()
    {
        var parent = NewDir();
        try
        {
            // Seven backup sets with strictly increasing creation times.
            var baseTime = DateTime.UtcNow.AddDays(-7);
            for (int i = 0; i < 7; i++)
            {
                var d = Path.Combine(parent, "set_" + i);
                Directory.CreateDirectory(d);
                Directory.SetCreationTimeUtc(d, baseTime.AddHours(i));
            }

            CleanerEngine.PruneOldBackups(parent, keep: 3);

            var remaining = Directory.GetDirectories(parent).Select(Path.GetFileName).OrderBy(x => x).ToList();
            Assert.Equal(3, remaining.Count);
            // The three newest (set_4, set_5, set_6) must survive.
            Assert.Equal(new[] { "set_4", "set_5", "set_6" }, remaining);
        }
        finally { Cleanup(parent); }
    }

    [Fact]
    public void PruneOldBackups_NoThrow_WhenParentMissing()
    {
        var missing = Path.Combine(Path.GetTempPath(), "dvtest_junk_missing_" + Guid.NewGuid().ToString("N"));
        CleanerEngine.PruneOldBackups(missing, keep: 3); // must not throw
        Assert.False(Directory.Exists(missing));
    }
}
