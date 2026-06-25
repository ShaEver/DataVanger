using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Classification;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;
using DataVanger.Detection;
using DataVanger.Engine;
using DataVanger.Memory;
using DataVanger.Memory.Readers;
using DataVanger.Memory.Rules;
using DataVanger.Reputation;
using static DataVanger.Tests.Fixtures.PeFactory;

// Phase 09 decomposition — ArchiveTraversal zip-bomb / entry-limit checks on a real
// in-memory ZIP (legacy section 14). Faithful verbatim move; private Assert shim ->
// LegacyAssert.True preserves condition + message. Self-contained (no cross-section
// locals). Filter: ~Archive.
public class ArchiveTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public void ArchiveTraversal_AllLegacyChecks()
    {
// 14. ArchiveTraversal — zip bomb / entry limits on a real in-memory ZIP
// ============================================================================

byte[] BuildZip(int entries, int entryBytes)
{
    using var ms = new MemoryStream();
    using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
    {
        for (int i = 0; i < entries; i++)
        {
            var entry = zip.CreateEntry($"entry-{i}.txt");
            using var es = entry.Open();
            byte[] payload = new byte[entryBytes];
            for (int j = 0; j < payload.Length; j++) payload[j] = (byte)('A' + (j % 26));
            es.Write(payload, 0, payload.Length);
        }
    }
    return ms.ToArray();
}

byte[] zipBytes = BuildZip(entries: 6, entryBytes: 128);

var smallProfile = new DataVanger.Engine.DeepScan.DeepScanProfileSettings
{
    Profile = ScanProfile.Deep,
    MaxArchiveDepth = 2,
    MaxArchiveEntries = 3,
    MaxTotalDecompressedBytes = 10_000,
    MaxCompressionRatio = 200,
    MaxNestedArchives = 4,
    MaxFileBytes = 0,
    MaxInMemoryEntryBytes = 4_096,
    MaxDegreeOfParallelism = 1,
    CpuThrottleDelayMs = 0,
    WorkQueueCapacity = 16,
    PerFileTimeout = TimeSpan.FromSeconds(5),
    PerArchiveTimeout = TimeSpan.FromSeconds(5),
    PerHashTimeout = TimeSpan.FromSeconds(5),
    OverallTimeout = TimeSpan.FromSeconds(30),
    InspectArchives = true,
    ResolveRealFileType = true,
    CorrelateEvidence = true,
    EmitStageTelemetry = false,
};

var rgArchive = new DataVanger.Engine.DeepScan.RecursionGuard(2, 4);
var zbArchive = new DataVanger.Engine.DeepScan.ZipBombGuard(10_000, 3, 200);

int admitted = 0;
bool sawAbort = false;
DataVanger.Engine.DeepScan.ArchiveAbortReason abortReason = DataVanger.Engine.DeepScan.ArchiveAbortReason.None;
using (var zs = new MemoryStream(zipBytes))
{
    foreach (var d in DataVanger.Engine.DeepScan.ArchiveTraversal.Walk(
                 zs, "memory://test.zip", currentDepth: 0,
                 smallProfile, rgArchive, zbArchive, CancellationToken.None))
    {
        if (d.IsAbort) { sawAbort = true; abortReason = d.AbortReason; break; }
        admitted++;
    }
}
Assert(sawAbort, "ArchiveTraversal must abort once the per-archive entry cap is exceeded.");
Assert(abortReason == DataVanger.Engine.DeepScan.ArchiveAbortReason.TooManyEntries,
    "Abort reason must be TooManyEntries when MaxArchiveEntries is the binding limit.");
Assert(admitted <= 3,
    "ArchiveTraversal must not yield more entries than the per-archive cap allows.");

// Depth-zero archive against a profile that disallows recursion altogether.
var noRecursion = new DataVanger.Engine.DeepScan.RecursionGuard(0, 0);
var zbAny = new DataVanger.Engine.DeepScan.ZipBombGuard(10_000_000, 1_000, 1_000);
using (var zs2 = new MemoryStream(zipBytes))
{
    bool firstWasAbort = false;
    foreach (var d in DataVanger.Engine.DeepScan.ArchiveTraversal.Walk(
                 zs2, "memory://noexpand.zip", currentDepth: 1,
                 smallProfile, noRecursion, zbAny, CancellationToken.None))
    {
        if (d.IsAbort && d.AbortReason == DataVanger.Engine.DeepScan.ArchiveAbortReason.MaxDepthReached)
        {
            firstWasAbort = true;
        }
        break;
    }
    Assert(firstWasAbort,
        "ArchiveTraversal must abort with MaxDepthReached when entered beyond the depth budget.");
}

// PendingWorkCounter contract
var counter = new DataVanger.Engine.DeepScan.PendingWorkCounter();
counter.Enqueued(); counter.Enqueued();
Assert(counter.Pending == 2, "PendingWorkCounter must reflect enqueued items.");
counter.Completed();
counter.MarkDiscoveryDone();
Assert(!counter.WaitForDrainAsync(CancellationToken.None).IsCompleted,
    "PendingWorkCounter must keep waiting until pending hits zero, even if discovery is done.");
counter.Completed();
Assert(counter.WaitForDrainAsync(CancellationToken.None).IsCompleted,
    "PendingWorkCounter must signal idle when both pending is 0 and discovery is done.");
    }
}
