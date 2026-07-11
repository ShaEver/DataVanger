using System;
using System.IO;
using System.Linq;
using System.Threading;
using DataVanger.Core;
using DataVanger.Engine;
using DataVanger.Infrastructure;

// Scan performance/profiling unit tests. Covers the safety-relevant primitives:
//   * TargetDiscovery.RemoveContainedPaths — canonical prefix-subsumption dedup
//     (eliminates the redundant double-walk without dropping any coverage);
//   * ScanStageProfiler — per-stage wall-time/count accumulation (diagnostics only);
//   * Sha256HashService — always recomputes current file bytes; its disk data is
//     bounded observation only, never a scan-skip or trust source.
// Filters: ~ScanPerformance, ~TargetDedup, ~StageProfiler, ~CacheSafety.
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
    public void HashObservations_NeverReuseHash_WhenBytesChangeButMetadataIsRestored()
    {
        string dir = Directory.CreateTempSubdirectory("dv_cache_").FullName;
        string cachePath = Path.Combine(dir, "hash_cache.json");
        string filePath = Path.Combine(dir, "a.exe");
        try
        {
            File.WriteAllText(filePath, "AAAA");
            var svc = new Sha256HashService(cachePath);
            var file = new FileInfo(filePath);
            string first = Xunit.Assert.IsType<string>(svc.ComputeSha256(file, out bool firstHit));
            Xunit.Assert.False(firstHit);
            svc.Persist();

            DateTime originalWrite = file.LastWriteTimeUtc;
            File.WriteAllText(filePath, "BBBB"); // same length, different bytes
            File.SetLastWriteTimeUtc(filePath, originalWrite); // attacker-restored metadata

            var reloaded = new Sha256HashService(cachePath);
            string second = Xunit.Assert.IsType<string>(reloaded.ComputeSha256(new FileInfo(filePath), out bool secondHit));
            Xunit.Assert.False(secondHit);
            Xunit.Assert.NotEqual(first, second);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Xunit.Fact]
    public void HashObservations_CorruptOrDuplicateJson_FailsClosedAndReportsHealth()
    {
        string dir = Directory.CreateTempSubdirectory("dv_cache_corrupt_").FullName;
        string cachePath = Path.Combine(dir, "hash_cache.json");
        try
        {
            File.WriteAllText(cachePath, "{\"Version\":1,\"Entries\":[{\"Path\":\"x\",\"Hash\":\"" + new string('A', 64) + "\",\"Length\":1},{\"Path\":\"x\",\"Hash\":\"" + new string('B', 64) + "\",\"Length\":1}]}");
            var svc = new Sha256HashService(cachePath);
            Xunit.Assert.True(svc.Health.IsDegraded);
            Xunit.Assert.Contains("duplicate", svc.Health.Reason);
        }
        finally { Directory.Delete(dir, true); }
    }

    private static bool Same(string a, string b) =>
        string.Equals(
            a.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            b.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase);
}
