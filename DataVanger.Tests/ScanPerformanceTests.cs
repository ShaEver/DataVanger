using System;
using System.IO;
using System.Linq;
using System.Threading;
using DataVanger.Core;
using DataVanger.Engine;
using DataVanger.Infrastructure;

// Beta 10 — scan performance/profiling unit tests. Covers the three additive,
// safety-relevant primitives introduced by the performance phase:
//   * TargetDiscovery.RemoveContainedPaths — canonical prefix-subsumption dedup
//     (eliminates the redundant double-walk without dropping any coverage);
//   * ScanStageProfiler — per-stage wall-time/count accumulation (diagnostics only);
//   * Sha256HashService clean-file cache — skips only unchanged, known-safe files
//     under an unchanged signature fingerprint (never bypasses a malicious check).
// Filters: ~ScanPerformance, ~TargetDedup, ~StageProfiler, ~CleanCache.
public class ScanPerformanceTests
{
    [Xunit.Fact]
    public void TargetDedup_RemoveContainedPaths_DropsNestedKeepsSiblings()
    {
        string root = Directory.CreateTempSubdirectory("dv_dedup_").FullName;
        string sibling = Directory.CreateTempSubdirectory("dv_dedup_sib_").FullName;
        try
        {
            string nested = Path.Combine(root, "child", "grand");
            Directory.CreateDirectory(nested);

            var result = TargetDiscovery.RemoveContainedPaths(new[] { root, nested, sibling, root });

            Xunit.Assert.Contains(result, p => Same(p, root));
            Xunit.Assert.DoesNotContain(result, p => Same(p, nested)); // subsumed by ancestor
            Xunit.Assert.Contains(result, p => Same(p, sibling));      // unrelated sibling survives
        }
        finally
        {
            Directory.Delete(root, true);
            Directory.Delete(sibling, true);
        }
    }

    [Xunit.Fact]
    public void TargetDedup_DoesNotSubsumeSimilarPrefix()
    {
        // "Users" must NOT subsume "UsersData" — containment is on a separator boundary.
        string baseDir = Directory.CreateTempSubdirectory("dv_prefix_").FullName;
        try
        {
            string users = Path.Combine(baseDir, "Users");
            string usersData = Path.Combine(baseDir, "UsersData");
            Directory.CreateDirectory(users);
            Directory.CreateDirectory(usersData);

            var result = TargetDiscovery.RemoveContainedPaths(new[] { users, usersData });

            Xunit.Assert.Equal(2, result.Count);
        }
        finally
        {
            Directory.Delete(baseDir, true);
        }
    }

    [Xunit.Fact]
    public void StageProfiler_AccumulatesPerStageElapsedAndCount()
    {
        var profiler = new ScanStageProfiler();
        using (profiler.Measure("A")) { Thread.Sleep(2); }
        profiler.Add("A", 0, 1); // count-only increment
        using (profiler.Measure("B")) { Thread.Sleep(1); }

        var snap = profiler.Snapshot();

        Xunit.Assert.Contains(snap, s => s.Stage == "A");
        Xunit.Assert.Contains(snap, s => s.Stage == "B");
        var a = snap.First(s => s.Stage == "A");
        Xunit.Assert.True(a.Elapsed > TimeSpan.Zero, "Stage A should record elapsed time.");
        Xunit.Assert.True(a.Count >= 2, "Stage A should accumulate counts from both calls.");
    }

    [Xunit.Fact]
    public void CleanCache_SkipsOnlyUnchangedKnownSafeUnderSameFingerprint()
    {
        string dir = Directory.CreateTempSubdirectory("dv_cache_").FullName;
        string cachePath = Path.Combine(dir, "hash_cache.json");
        string filePath = Path.Combine(dir, "a.exe");
        try
        {
            File.WriteAllText(filePath, "hello");
            var svc = new Sha256HashService(cachePath);
            var file = new FileInfo(filePath);

            // No cache entry yet -> never a clean skip.
            Xunit.Assert.False(svc.TryCleanSkip(file, "fp1"));

            // Seed the hash entry, then record a known-safe verdict under fingerprint fp1.
            svc.ComputeSha256(file, out _);
            svc.TouchScore(filePath, 0, knownSafe: true, "fp1");
            file.Refresh();
            Xunit.Assert.True(svc.TryCleanSkip(file, "fp1"),
                "Unchanged known-safe file must be skippable under the same fingerprint.");

            // Different fingerprint (signatures changed) -> must NOT skip.
            Xunit.Assert.False(svc.TryCleanSkip(file, "fp2"));

            // Empty fingerprint -> must NOT skip.
            Xunit.Assert.False(svc.TryCleanSkip(file, ""));

            // A non-clean (suspicious) verdict must never be skippable.
            svc.TouchScore(filePath, 7, knownSafe: false, "fp1");
            Xunit.Assert.False(svc.TryCleanSkip(file, "fp1"));

            // Content change invalidates a previously clean entry.
            svc.TouchScore(filePath, 0, knownSafe: true, "fp1");
            Thread.Sleep(10);
            File.WriteAllText(filePath, "hello world (content changed)");
            var changed = new FileInfo(filePath);
            Xunit.Assert.False(svc.TryCleanSkip(changed, "fp1"));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static bool Same(string a, string b) =>
        string.Equals(
            a.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            b.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase);
}
