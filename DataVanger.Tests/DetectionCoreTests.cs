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

// Phase 09 decomposition — detection-core cluster (legacy sections 1,2,3,4,6,7,10,13,16).
// The mega-[Fact] shared setup state (heuristicEvidence, confirmedEvidence, classifier,
// dummyContext) across these sections. That state is reconstructed here verbatim via the
// builders below so each [Fact] is self-contained; each Fact prepends only the shared
// locals it consumes (per the two-way coupling analysis). Assertions and expected values
// are preserved verbatim; the private Assert shim delegates to LegacyAssert.True.
// Filters: ~DetectionCore, ~Classifier, ~DetectionPipeline, ~PeAnalyzer, ~ZipBomb,
// ~DeepScan, ~AntiFp.
public class DetectionCoreTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    private static List<Evidence> NewHeuristicEvidence() => new List<Evidence>
    {
        new() { Category = "Heuristic", Description = "Dupla extensão disfarçada", ScoreDelta = 8, Strength = EvidenceStrength.High },
        new() { Category = "Script", Description = "PowerShell EncodedCommand", ScoreDelta = 5, Strength = EvidenceStrength.High },
    };

    private static List<Evidence> NewConfirmedEvidence() => new List<Evidence>
    {
        new() { Category = "Reputation", Description = "Hash bate com base de malware", ScoreDelta = 100,
                Strength = EvidenceStrength.Confirmed, CanConfirmMalware = true },
    };

    private static ScanContext NewDummyContext() => new ScanContext(
        new ScanOptions { Profile = ScanProfile.Deep },
        new AppSettings(),
        runningProcessPaths: Array.Empty<string>(),
        persistenceExactPaths: Array.Empty<string>(),
        persistenceBlob: "");

    [Xunit.Fact]
    public void AntiFpStaticPolicy_AllLegacyChecks()
    {
// 1. Anti-false-positive contract (legacy static policy)
// ============================================================================

var heuristicOnly = new ScanFinding
{
    Path = @"C:\Users\Test\AppData\Roaming\svchost.exe",
    Score = RiskThresholds.Critical + 20,
    Reasons = "Nome de processo de sistema fora de System32; execução dinâmica; persistência"
};
Assert(ThreatClassificationPolicy.Classify(heuristicOnly) == ThreatClass.HighRisk,
    "Heuristics alone must not classify as confirmed malware.");
Assert(!ThreatClassificationPolicy.AllowsAutomaticAction(heuristicOnly),
    "Heuristics alone must not allow automatic action.");

var blacklisted = new ScanFinding
{
    Path = @"C:\Users\Test\Downloads\payload.exe",
    Score = RiskThresholds.Critical,
    IsBlacklisted = true
};
Assert(ThreatClassificationPolicy.Classify(blacklisted) == ThreatClass.ConfirmedMalware,
    "Blacklist hash must classify as confirmed malware.");
Assert(ThreatClassificationPolicy.AllowsAutomaticAction(blacklisted),
    "Confirmed malware may allow automatic action.");

var confirmedRule = new ScanFinding
{
    Path = @"C:\Users\Test\Downloads\payload.exe",
    Score = RiskThresholds.Critical,
    HasConfirmedSignature = true
};
Assert(ThreatClassificationPolicy.Classify(confirmedRule) == ThreatClass.ConfirmedMalware,
    "Confirmed signature must classify as confirmed malware.");

var nonConfirmedRule = new ScanFinding
{
    Path = @"C:\Users\Test\Downloads\suspicious.ps1",
    Score = RiskThresholds.High,
    HasConfirmedSignature = false
};
Assert(ThreatClassificationPolicy.Classify(nonConfirmedRule) == ThreatClass.HighRisk,
    "Non-confirmed signatures or heuristics should remain high risk.");

var clean = new ScanFinding
{
    Path = @"C:\Windows\System32\notepad.exe",
    Score = 0,
    IsSigned = true,
    Publisher = "Microsoft Windows"
};
Assert(ThreatClassificationPolicy.Classify(clean) == ThreatClass.Clean,
    "Signed clean item with no score should remain clean.");

    }

    [Xunit.Fact]
    public void AntiFpPolicyHelper_AllLegacyChecks()
    {
// 2. Anti-false-positive policy helper (centralised version of the same rule)
// ============================================================================

var heuristicEvidence = new List<Evidence>
{
    new() { Category = "Heuristic", Description = "Dupla extensão disfarçada", ScoreDelta = 8, Strength = EvidenceStrength.High },
    new() { Category = "Script", Description = "PowerShell EncodedCommand", ScoreDelta = 5, Strength = EvidenceStrength.High },
};
Assert(!AntiFalsePositivePolicy.HasConfirmedEvidence(heuristicEvidence),
    "Heuristic-only evidence must not be reported as confirmed.");

var confirmedEvidence = new List<Evidence>
{
    new() { Category = "Reputation", Description = "Hash bate com base de malware", ScoreDelta = 100,
            Strength = EvidenceStrength.Confirmed, CanConfirmMalware = true },
};
Assert(AntiFalsePositivePolicy.HasConfirmedEvidence(confirmedEvidence),
    "Confirmed evidence must be recognised.");

int clamped = AntiFalsePositivePolicy.ClampToHighRiskWhenUnconfirmed(
    score: RiskThresholds.Critical + 50,
    finding: new ScanFinding(),
    evidence: heuristicEvidence);
Assert(clamped == RiskThresholds.High,
    "Critical score with heuristic-only evidence must be clamped to High.");

    }

    [Xunit.Fact]
    public async Task Classifier_AllLegacyChecks()
    {
        var heuristicEvidence = NewHeuristicEvidence();
        var confirmedEvidence = NewConfirmedEvidence();
// 3. Classifier produces evidence-rich verdicts
// ============================================================================

IThreatClassifier classifier = new ThreatClassifier();
var dummyContext = new ScanContext(
    new ScanOptions { Profile = ScanProfile.Deep },
    new AppSettings(),
    runningProcessPaths: Array.Empty<string>(),
    persistenceExactPaths: Array.Empty<string>(),
    persistenceBlob: "");

var heuristicFinding = new ScanFinding { Score = 9, Path = @"C:\Users\T\AppData\bad.exe" };
var heuristicVerdict = classifier.Classify(heuristicFinding, heuristicEvidence, dummyContext);
Assert(heuristicVerdict.ThreatClass == ThreatClass.HighRisk,
    "Classifier must return HighRisk for heuristic-only evidence with score 9.");
Assert(!heuristicVerdict.IsConfirmedMalware,
    "Classifier must never confirm malware on heuristics alone.");
Assert(!heuristicVerdict.AllowsAutomaticAction,
    "Classifier must not authorize automatic action on heuristic findings.");
Assert(heuristicVerdict.Evidence.Count == heuristicEvidence.Count,
    "Verdict must preserve the supplied evidence list.");

var hashFinding = new ScanFinding { IsBlacklisted = true, Score = 10 };
var hashVerdict = classifier.Classify(hashFinding, confirmedEvidence, dummyContext);
Assert(hashVerdict.IsConfirmedMalware,
    "Classifier must confirm malware when a hash hit is present.");
Assert(hashVerdict.AllowsAutomaticAction,
    "Classifier must authorize action on confirmed malware.");

var conflictingHash = new string('A', 64);
var conflictingSignatures = new SignatureDatabase();
conflictingSignatures.KnownSafe.Add(conflictingHash);
conflictingSignatures.UserWhitelist.Add(conflictingHash);
conflictingSignatures.KnownMalicious.Add(conflictingHash);
Assert(conflictingSignatures.IsKnownMalicious(conflictingHash),
    "A hash present in both safe and malicious databases must be malicious.");
Assert(!conflictingSignatures.IsKnownSafe(conflictingHash),
    "Known-malicious entries must not also be treated as known-safe.");

var hashTarget = new ScanTarget(new FileInfo(typeof(int).Assembly.Location)) { Sha256 = conflictingHash };
var hashModule = new HashDetectionModule(new DataVanger.Infrastructure.SignatureService(conflictingSignatures));
var hashEvidence = await hashModule.AnalyzeAsync(hashTarget, dummyContext, CancellationToken.None);
Assert(hashTarget.IsKnownMalicious && hashTarget.TrustState == FileTrustState.KnownMalicious,
    "Hash module must give malicious reputation precedence over whitelist state.");
Assert(hashEvidence.Any(e => e.CanConfirmMalware),
    "Blacklist-over-whitelist must still produce confirmed evidence.");

    }

    [Xunit.Fact]
    public async Task DetectionModuleExceptionIsolation_AllLegacyChecks()
    {
        var dummyContext = NewDummyContext();
// 4. Detection module exception isolation
// ============================================================================

var faultyModule = new ThrowingModule();
var emptyResult = await faultyModule.AnalyzeAsync(
    new ScanTarget(new FileInfo(typeof(int).Assembly.Location)),
    dummyContext,
    CancellationToken.None);
Assert(emptyResult.Count == 0,
    "A module that throws must yield zero evidence, never crash the pipeline.");

    }

    [Xunit.Fact]
    public async Task DetectionPipeline_AllLegacyChecks()
    {
        IThreatClassifier classifier = new ThreatClassifier();
        var dummyContext = NewDummyContext();
// 6. DetectionPipeline aggregates evidence and detects confirmed signals
// ============================================================================

var registry = new DetectionModuleRegistry(new IDetectionModule[]
{
    new FixedEvidenceModule("M1",
        new Evidence { Category = "Heuristic", Description = "h1", ScoreDelta = 3, Strength = EvidenceStrength.Medium }),
    new FixedEvidenceModule("M2",
        new Evidence { Category = "Reputation", Description = "confirmed", ScoreDelta = 50,
                       Strength = EvidenceStrength.Confirmed, CanConfirmMalware = true }),
});
var pipeline = new DetectionPipeline(registry, classifier,
    new DataVanger.Infrastructure.DelegateScanLogger(_ => { }));
var outcome = await pipeline.AnalyzeAsync(
    new ScanTarget(new FileInfo(typeof(int).Assembly.Location)),
    dummyContext,
    CancellationToken.None);

Assert(outcome.AggregatedScore == 53,
    "Pipeline must sum all module ScoreDeltas.");
Assert(outcome.AnyConfirmedEvidence,
    "Pipeline must surface confirmed evidence to the engine.");
Assert(outcome.Modules.Count == 2,
    "Pipeline must record one ModuleResult per producing module.");

var knownSafePipeline = new DetectionPipeline(
    new DetectionModuleRegistry(new IDetectionModule[]
    {
        new TrustStateModule(FileTrustState.KnownSafe),
        new FixedEvidenceModule("SkippedHeuristic",
            new Evidence { Category = "Heuristic", Description = "must not run", ScoreDelta = 100, Strength = EvidenceStrength.High }),
        new FixedEvidenceModule("ConfirmedYara",
            new Evidence { Category = "Signature", Description = "confirmed YARA", ScoreDelta = 50,
                           Strength = EvidenceStrength.Confirmed, CanConfirmMalware = true },
            DetectionModuleCapabilities.CanConfirmMalware),
    }),
    classifier,
    new DataVanger.Infrastructure.DelegateScanLogger(_ => { }));
var knownSafeOutcome = await knownSafePipeline.AnalyzeAsync(
    new ScanTarget(new FileInfo(typeof(int).Assembly.Location)),
    dummyContext,
    CancellationToken.None);
Assert(knownSafeOutcome.AnyConfirmedEvidence,
    "Known-safe short-circuit must not hide confirmed malware evidence.");
Assert(knownSafeOutcome.AggregatedScore == 50,
    "Known-safe short-circuit should skip heuristic-only modules while preserving confirmed modules.");

    }

    [Xunit.Fact]
    public void AntiFpClamp_AllLegacyChecks()
    {
        var confirmedEvidence = NewConfirmedEvidence();
// 7. Anti-FP clamp must NOT clamp confirmed findings
// ============================================================================

var confirmedFinding = new ScanFinding { IsBlacklisted = true, Score = 100 };
int notClamped = AntiFalsePositivePolicy.ClampToHighRiskWhenUnconfirmed(100, confirmedFinding, confirmedEvidence);
Assert(notClamped == 100,
    "Confirmed findings must NOT be clamped — they keep their full score.");

    }

    [Xunit.Fact]
    public async Task ZipBombGuardAndArchiveTraversal_AllLegacyChecks()
    {
        var dummyContext = NewDummyContext();
// 10. ZipBombGuard
// ============================================================================

var zb = new DataVanger.Engine.DeepScan.ZipBombGuard(
    maxTotalDecompressedBytes: 1_000,
    maxEntries: 2,
    maxCompressionRatio: 50);
Assert(zb.TryAdmit(100, 10).Allowed, "ZipBombGuard must admit reasonable entries.");
var ratioDeny = zb.TryAdmit(10_000, 1);
Assert(!ratioDeny.Allowed && ratioDeny.Reason == DataVanger.Engine.DeepScan.ZipBombReason.RatioExceeded,
    "ZipBombGuard must deny pathological ratios.");
var tooMany = zb.TryAdmit(50, 10);
Assert(!tooMany.Allowed && tooMany.Reason == DataVanger.Engine.DeepScan.ZipBombReason.TooManyEntries,
    "ZipBombGuard must enforce the per-archive entry count.");

var zb2 = new DataVanger.Engine.DeepScan.ZipBombGuard(maxTotalDecompressedBytes: 500, maxEntries: 100, maxCompressionRatio: 1_000);
Assert(zb2.TryAdmit(400, 100).Allowed, "First admission must fit the budget.");
var overflow = zb2.TryAdmit(200, 100);
Assert(!overflow.Allowed && overflow.Reason == DataVanger.Engine.DeepScan.ZipBombReason.DecompressedSizeExceeded,
    "ZipBombGuard must deny once the cumulative decompressed budget is exceeded.");
Assert(zb2.DecompressedBytes == 400,
    "ZipBombGuard must roll back denied admissions instead of leaking the budget.");

// ============================================================================
// 10b. ArchiveTraversal behavior and safety budgets
// ============================================================================

var archiveProfile = new DataVanger.Engine.DeepScan.DeepScanProfileSettings
{
    Profile = ScanProfile.Deep,
    MaxArchiveDepth = 2,
    MaxArchiveEntries = 10,
    MaxTotalDecompressedBytes = 2_000_000,
    MaxCompressionRatio = 1_000,
    MaxNestedArchives = 10,
    MaxInMemoryEntryBytes = 1024,
    InspectArchives = true,
    MaxDegreeOfParallelism = 1,
};

var validZipBytes = CreateZip(("nested/ok.txt", System.Text.Encoding.ASCII.GetBytes("ok")));
using (var zipStream = new MemoryStream(validZipBytes))
{
    var descriptors = DataVanger.Engine.DeepScan.ArchiveTraversal.Walk(
        zipStream, "root.zip", 0, archiveProfile,
        new DataVanger.Engine.DeepScan.RecursionGuard(2, 10),
        new DataVanger.Engine.DeepScan.ZipBombGuard(1_000_000, 10, 1_000),
        CancellationToken.None).ToList();
    Assert(descriptors.Count == 1 && descriptors[0].EntryName == "nested/ok.txt",
        "ArchiveTraversal must yield valid ZIP entries.");
    var smallEntryBuffer = descriptors[0].Buffer;
    Assert(smallEntryBuffer != null && System.Text.Encoding.ASCII.GetString(smallEntryBuffer) == "ok",
        "ArchiveTraversal must buffer small entries within the memory budget.");
}

using (var malformed = new MemoryStream(new byte[] { 1, 2, 3, 4 }))
{
    var descriptors = DataVanger.Engine.DeepScan.ArchiveTraversal.Walk(
        malformed, "bad.zip", 0, archiveProfile,
        new DataVanger.Engine.DeepScan.RecursionGuard(2, 10),
        new DataVanger.Engine.DeepScan.ZipBombGuard(1_000_000, 10, 1_000),
        CancellationToken.None).ToList();
    Assert(descriptors.Count == 1 && descriptors[0].AbortReason == DataVanger.Engine.DeepScan.ArchiveAbortReason.MalformedArchive,
        "Malformed archives must surface a MalformedArchive abort descriptor.");
}

var twoEntryZip = CreateZip(
    ("one.txt", System.Text.Encoding.ASCII.GetBytes("1")),
    ("two.txt", System.Text.Encoding.ASCII.GetBytes("2")));
var entryCapProfile = new DataVanger.Engine.DeepScan.DeepScanProfileSettings
{
    Profile = ScanProfile.Deep,
    MaxArchiveDepth = 2,
    MaxArchiveEntries = 1,
    MaxTotalDecompressedBytes = 2_000_000,
    MaxCompressionRatio = 1_000,
    MaxNestedArchives = 10,
    MaxInMemoryEntryBytes = 1024,
    InspectArchives = true,
    MaxDegreeOfParallelism = 1,
};
using (var zipStream = new MemoryStream(twoEntryZip))
{
    var descriptors = DataVanger.Engine.DeepScan.ArchiveTraversal.Walk(
        zipStream, "many.zip", 0, entryCapProfile,
        new DataVanger.Engine.DeepScan.RecursionGuard(2, 10),
        new DataVanger.Engine.DeepScan.ZipBombGuard(1_000_000, 10, 1_000),
        CancellationToken.None).ToList();
    Assert(descriptors.Any(d => d.AbortReason == DataVanger.Engine.DeepScan.ArchiveAbortReason.TooManyEntries),
        "ArchiveTraversal must abort when the per-archive entry cap is exceeded.");
}

var traversalZip = CreateZip(("../evil.exe", new byte[] { 1, 2, 3 }));
using (var zipStream = new MemoryStream(traversalZip))
{
    var descriptors = DataVanger.Engine.DeepScan.ArchiveTraversal.Walk(
        zipStream, "traversal.zip", 0, archiveProfile,
        new DataVanger.Engine.DeepScan.RecursionGuard(2, 10),
        new DataVanger.Engine.DeepScan.ZipBombGuard(1_000_000, 10, 1_000),
        CancellationToken.None).ToList();
    Assert(descriptors.Any(d => d.Suspicion == DataVanger.Engine.DeepScan.ArchiveSuspicion.PathTraversal),
        "ArchiveTraversal must flag path traversal entries without extracting them.");
}

using (var zipStream = new MemoryStream(validZipBytes))
{
    var descriptors = DataVanger.Engine.DeepScan.ArchiveTraversal.Walk(
        zipStream, "too-deep.zip", 1, archiveProfile,
        new DataVanger.Engine.DeepScan.RecursionGuard(0, 10),
        new DataVanger.Engine.DeepScan.ZipBombGuard(1_000_000, 10, 1_000),
        CancellationToken.None).ToList();
    Assert(descriptors.Count == 1 && descriptors[0].AbortReason == DataVanger.Engine.DeepScan.ArchiveAbortReason.MaxDepthReached,
        "ArchiveTraversal must abort before walking archives beyond the recursion depth limit.");
}

var bombZip = CreateZip(("bomb.bin", System.Text.Encoding.ASCII.GetBytes(new string('A', 4096))));
using (var zipStream = new MemoryStream(bombZip))
{
    var descriptors = DataVanger.Engine.DeepScan.ArchiveTraversal.Walk(
        zipStream, "bomb.zip", 0, archiveProfile,
        new DataVanger.Engine.DeepScan.RecursionGuard(2, 10),
        new DataVanger.Engine.DeepScan.ZipBombGuard(1_000_000, 10, 1),
        CancellationToken.None).ToList();
    Assert(descriptors.Any(d => d.AbortReason == DataVanger.Engine.DeepScan.ArchiveAbortReason.CompressionRatioExceeded),
        "ArchiveTraversal must abort entries whose decompressed/compressed ratio exceeds the budget.");
}

var largeEntryProfile = new DataVanger.Engine.DeepScan.DeepScanProfileSettings
{
    Profile = ScanProfile.Deep,
    MaxArchiveDepth = 2,
    MaxArchiveEntries = 10,
    MaxTotalDecompressedBytes = 2_000_000,
    MaxCompressionRatio = 1_000,
    MaxNestedArchives = 10,
    MaxInMemoryEntryBytes = 8,
    InspectArchives = true,
    MaxDegreeOfParallelism = 1,
};
using (var zipStream = new MemoryStream(CreateZip(("large.bin", Enumerable.Range(0, 1_048_576).Select(i => (byte)(i % 251)).ToArray()))))
{
    var descriptors = DataVanger.Engine.DeepScan.ArchiveTraversal.Walk(
        zipStream, "large.zip", 0, largeEntryProfile,
        new DataVanger.Engine.DeepScan.RecursionGuard(2, 10),
        new DataVanger.Engine.DeepScan.ZipBombGuard(2_000_000, 10, 1_000),
        CancellationToken.None).ToList();
    Assert(descriptors.Count == 1 && descriptors[0].Buffer == null,
        "Large archive entries must be surfaced without being buffered into memory.");
}

using (var zipStream = new MemoryStream(validZipBytes))
using (var cts = new CancellationTokenSource())
{
    cts.Cancel();
    bool cancelledArchiveWalk = false;
    try
    {
        _ = DataVanger.Engine.DeepScan.ArchiveTraversal.Walk(
            zipStream, "cancelled.zip", 0, archiveProfile,
            new DataVanger.Engine.DeepScan.RecursionGuard(2, 10),
            new DataVanger.Engine.DeepScan.ZipBombGuard(1_000_000, 10, 1_000),
            cts.Token).ToList();
    }
    catch (OperationCanceledException)
    {
        cancelledArchiveWalk = true;
    }
    Assert(cancelledArchiveWalk,
        "ArchiveTraversal must honor cancellation during archive enumeration.");
}
var fullQueue = System.Threading.Channels.Channel.CreateBounded<DataVanger.Engine.DeepScan.ScanWorkItem>(1);
{
    Assert(fullQueue.Writer.TryWrite(new DataVanger.Engine.DeepScan.ScanWorkItem(
        new DataVanger.Engine.DeepScan.MemoryContentSource("occupied.bin", new byte[] { 1 }, "queue-test"), 0)),
        "Test setup must fill the bounded queue.");

    var pending = new DataVanger.Engine.DeepScan.PendingWorkCounter();
    var telemetry = new DataVanger.Engine.DeepScan.DeepScanTelemetry();
    using var throttle = new DataVanger.Engine.DeepScan.ScanThrottle(1, 0);
    var queueContext = new DataVanger.Engine.DeepScan.DeepScanContext(
        archiveProfile,
        dummyContext,
        telemetry,
        throttle,
        fullQueue.Writer,
        new DetectionModuleRegistry(Array.Empty<IDetectionModule>()),
        new DataVanger.Infrastructure.DelegateScanLogger(_ => { }),
        pending);
    var archiveItem = new DataVanger.Engine.DeepScan.ScanWorkItem(
        new DataVanger.Engine.DeepScan.MemoryContentSource("queue.zip", validZipBytes, "queue-test"), 0)
    {
        SniffedType = DataVanger.Engine.DeepScan.SniffedFileType.ZipFamily,
    };

    await new DataVanger.Engine.DeepScan.Stages.ArchiveExpansionStage()
        .ExecuteAsync(archiveItem, queueContext, CancellationToken.None);

    Assert(pending.Pending == 0,
        "ArchiveExpansionStage must complete pending accounting when a bounded queue rejects a child item.");
    Assert(archiveItem.Evidence.Any(e => e.Description.Contains("fila de análise", StringComparison.OrdinalIgnoreCase)),
        "ArchiveExpansionStage must record evidence instead of blocking when the queue is full.");
}
    }

    [Xunit.Fact]
    public async Task DeepScanOrchestration_AllLegacyChecks()
    {
// 13. Deep Scan Pipeline — orchestration & cancellation
// ============================================================================

string scratch = Path.Combine(Path.GetTempPath(), "datavanger-deepscan-tests");
try { Directory.Delete(scratch, recursive: true); } catch (Exception) { /* temp cleanup - ignore if already removed */ }
Directory.CreateDirectory(scratch);
var f1 = Path.Combine(scratch, "a.exe"); File.WriteAllBytes(f1, new byte[] { (byte)'M', (byte)'Z', 0, 0 });
var f2 = Path.Combine(scratch, "b.txt"); File.WriteAllText(f2, "hello deep scan");

var pipelineSettings = new AppSettings();
var pipelineOptions = new ScanOptions { Profile = ScanProfile.Deep, UseDeepScanPipeline = true };
var pipelineContext = new ScanContext(
    pipelineOptions, pipelineSettings,
    runningProcessPaths: Array.Empty<string>(),
    persistenceExactPaths: Array.Empty<string>(),
    persistenceBlob: "");

var pipelineLogger = new DataVanger.Infrastructure.DelegateScanLogger(_ => { });
var emptySigs = new SignatureDatabase();
var sigSvc = new DataVanger.Infrastructure.SignatureService(emptySigs);
var deepScanRegistry = new DetectionModuleRegistry(new IDetectionModule[]
{
    new FixedEvidenceModule("Sentinel",
        new Evidence { Category = "Heuristic", Description = "sentinel hit", ScoreDelta = 7, Strength = EvidenceStrength.High }),
});
var localPipeline = new DetectionPipeline(deepScanRegistry, new DataVanger.Classification.ThreatClassifier(), pipelineLogger);

var deepResult = await DataVanger.Engine.DeepScan.DeepScanRunner.RunAsync(
    new[] { scratch }, pipelineOptions, pipelineSettings, deepScanRegistry, localPipeline, sigSvc,
    new DataVanger.Infrastructure.ResilientFileSystemService(), pipelineLogger, pipelineContext,
    CancellationToken.None);

Assert(deepResult.Telemetry.Discovered >= 2,
    "Deep scan must discover both seeded files.");
Assert(deepResult.Items.Length >= 1,
    "Deep scan must produce at least one finding from the sentinel module.");
Assert(deepResult.Items.Any(it => it.Sha256 != null),
    "Deep scan must compute SHA-256 hashes for at least one item.");
Assert(deepResult.Items.Any(it => it.SniffedType == DataVanger.Engine.DeepScan.SniffedFileType.Pe),
    "Deep scan must detect the MZ magic bytes for a.exe.");
Assert(!deepResult.Cancelled,
    "Deep scan must complete without cancellation when no cancel is requested.");

// Cancellation safety: an already-cancelled token must return quickly without throwing externally.
using var cancelled = new CancellationTokenSource();
cancelled.Cancel();
var cancelledResult = await DataVanger.Engine.DeepScan.DeepScanRunner.RunAsync(
    new[] { scratch }, pipelineOptions, pipelineSettings, deepScanRegistry, localPipeline, sigSvc,
    new DataVanger.Infrastructure.ResilientFileSystemService(), pipelineLogger, pipelineContext,
    cancelled.Token);
Assert(cancelledResult.Cancelled,
    "Deep scan must surface the cancellation in DeepScanResult.Cancelled.");

try { Directory.Delete(scratch, recursive: true); } catch (Exception) { /* temp cleanup - ignore if already removed */ }

    }

    [Xunit.Fact]
    public async Task PeAnalyzer_AllLegacyChecks()
    {
        IThreatClassifier classifier = new ThreatClassifier();
        var dummyContext = NewDummyContext();
// 16. PE Analyzer - modular parser, explainable evidence and anti-FP safety
// ============================================================================

const uint PeRead = 0x40000000;
const uint PeWrite = 0x80000000;
const uint PeExecute = 0x20000000;
var importText = System.Text.Encoding.ASCII.GetBytes("VirtualAlloc WriteProcessMemory CreateRemoteThread LoadLibraryA GetProcAddress InternetOpen WinExec IsDebuggerPresent CryptUnprotectData");
var rsrcBytes = new byte[2048];
System.Text.Encoding.ASCII.GetBytes("resource-header MZ powershell cmd.exe").CopyTo(rsrcBytes, 32);
var suspiciousPeBytes = CreateTestPe(new[]
{
    ("UPX0", PeRead | PeExecute, PatternBytes(8192), 8192u),
    (".rwx", PeRead | PeWrite | PeExecute, importText, 4096u),
    (".rsrc", PeRead, rsrcBytes, 4096u),
}, System.Text.Encoding.ASCII.GetBytes("PK\u0003\u0004MZ" + new string('A', 32_000)));

using (var suspiciousStream = new MemoryStream(suspiciousPeBytes))
{
    Assert(DataVanger.Detection.PE.PeParser.IsPeFile(suspiciousStream),
        "PE parser must identify valid MZ/PE headers from a stream.");
}
var parsedPe = DataVanger.Detection.PE.PeParser.Parse(new MemoryStream(suspiciousPeBytes), "archive:payload.bin");
Assert(parsedPe.IsPe && parsedPe.ParsedSuccessfully && parsedPe.File?.Sections.Count == 3,
    "PE parser must parse a valid minimal PE and section table.");
var peResult = DataVanger.Detection.PE.PeAnalyzer.Analyze(new MemoryStream(suspiciousPeBytes), "archive:payload.bin");
Assert(peResult.Evidence.Any(e => e.Description.Contains("packer", StringComparison.OrdinalIgnoreCase)),
    "PE analyzer must explain packer section indicators.");
Assert(peResult.Evidence.Any(e => e.Description.Contains("Alta entropia", StringComparison.OrdinalIgnoreCase)),
    "PE analyzer must emit entropy evidence.");
Assert(peResult.Evidence.Any(e => e.Description.Contains("injeção", StringComparison.OrdinalIgnoreCase)),
    "PE analyzer must group suspicious injection imports as heuristic evidence.");
Assert(peResult.Evidence.Any(e => e.Description.Contains("Overlay", StringComparison.OrdinalIgnoreCase)),
    "PE analyzer must detect appended overlay data.");
Assert(peResult.Evidence.Any(e => e.Description.Contains("Recurso", StringComparison.OrdinalIgnoreCase)),
    "PE analyzer must detect basic resource payload indicators.");
Assert(peResult.Evidence.Any(e => e.Description.Contains("Correlação PE", StringComparison.OrdinalIgnoreCase)),
    "PE correlation engine must emit explainable correlation evidence.");
Assert(peResult.Evidence.All(e => !e.CanConfirmMalware),
    "PE analyzer evidence must never be confirmable malware by itself.");

var peFinding = new ScanFinding { Path = @"C:\Users\T\Downloads\packed.exe", Score = peResult.Score, Evidence = peResult.Evidence.ToList() };
Assert(ThreatClassificationPolicy.Classify(peFinding) == ThreatClass.HighRisk,
    "Packed/suspicious PE heuristics must remain HighRisk, not ConfirmedMalware.");
Assert(!ThreatClassificationPolicy.AllowsAutomaticAction(peFinding),
    "PE heuristics must not allow automatic quarantine.");

var malformedPe = new byte[128];
malformedPe[0] = (byte)'M'; malformedPe[1] = (byte)'Z';
BitConverter.GetBytes(0x7FFFFF00).CopyTo(malformedPe, 0x3C);
var malformedResult = DataVanger.Detection.PE.PeAnalyzer.Analyze(new MemoryStream(malformedPe), "bad.exe");
Assert(malformedResult.Evidence.Count == 0 || malformedResult.Evidence.All(e => e.Category == "PE"),
    "Malformed PE parsing must degrade into PE evidence or no evidence, never throw.");

string peTestDir = Path.Combine(Path.GetTempPath(), "datavanger-pe-tests");
Directory.CreateDirectory(peTestDir);
string disguisedPath = Path.Combine(peTestDir, "payload.txt");
File.WriteAllBytes(disguisedPath, suspiciousPeBytes);
var disguisedTarget = new ScanTarget(new FileInfo(disguisedPath));
var peModule = new PeDetectionModule();
Assert(peModule.Supports(disguisedTarget, dummyContext),
    "PE detection module must support PE content hidden behind a fake extension.");
var disguisedEvidence = await peModule.AnalyzeAsync(disguisedTarget, dummyContext, CancellationToken.None);
Assert(disguisedEvidence.Count > 0 && disguisedEvidence.Any(e => e.Category == "PE"),
    "PE detection module must return PE evidence for fake-extension payloads.");

var pePipeline = new DetectionPipeline(
    new DetectionModuleRegistry(new IDetectionModule[] { new PeDetectionModule() }),
    classifier,
    new DataVanger.Infrastructure.DelegateScanLogger(_ => { }));
var pePipelineOutcome = await pePipeline.AnalyzeAsync(disguisedTarget, dummyContext, CancellationToken.None);
Assert(pePipelineOutcome.Modules.Any(m => m.ModuleName == "PeStatic") && pePipelineOutcome.Evidence.Any(e => e.Category == "PE"),
    "PE analyzer must integrate into the DetectionPipeline through PeDetectionModule.");
try { Directory.Delete(peTestDir, recursive: true); } catch (Exception) { /* temp cleanup - ignore if already removed */ }

var benignPeBytes = CreateTestPe(new[]
{
    (".text", PeRead | PeExecute, System.Text.Encoding.ASCII.GetBytes("normal bootstrap data"), 4096u),
    (".rsrc", PeRead, System.Text.Encoding.ASCII.GetBytes("version info"), 4096u),
});
var benignResult = DataVanger.Detection.PE.PeAnalyzer.Analyze(new MemoryStream(benignPeBytes), "benign.exe");
Assert(benignResult.Score <= 2,
    "Benign-looking PE structure must stay low score to reduce false positives.");
Assert(benignResult.Evidence.All(e => !e.CanConfirmMalware),
    "Benign PE evidence must not become confirmable malware.");

// FASE 4 — verify single open+parse consolidation: AnalyzeWithFile exposes parsed PE
// with section entropy already populated, and PeDetectionModule correctly builds
// the descriptive entropy map from it (zero additional I/O).
string peTestDir2 = Path.Combine(Path.GetTempPath(), "datavanger-pe-fase4-tests");
Directory.CreateDirectory(peTestDir2);
string packedPath = Path.Combine(peTestDir2, "packed.exe");
File.WriteAllBytes(packedPath, suspiciousPeBytes);

var (analysisResult, peFile) = DataVanger.Detection.PE.PeAnalyzer.AnalyzeWithFile(packedPath);
Assert(peFile is not null && peFile.Sections.Count == 3,
    "AnalyzeWithFile must return the parsed PeFile with sections.");
Assert(peFile!.Sections.Any(s => s.Entropy >= 7.2),
    "PeSectionAnalyzer must populate section.Entropy during the first parse.");
Assert(analysisResult.Evidence.Count > 0 && analysisResult.Evidence.Any(e => e.Description.Contains("Alta entropia", StringComparison.OrdinalIgnoreCase)),
    "First parse must emit entropy evidence as usual.");

var packedTarget = new ScanTarget(new FileInfo(packedPath));
var peModule2 = new PeDetectionModule();
var packedEvidence = await peModule2.AnalyzeAsync(packedTarget, dummyContext, CancellationToken.None);
Assert(packedEvidence.Any(e => e.Category == "PE" && e.Description.Contains("Elevated entropy", StringComparison.OrdinalIgnoreCase)),
    "PeDetectionModule must still emit the descriptive entropy enrichment from the reused parsed sections.");
Assert(packedEvidence.All(e => e.ScoreDelta == 0 || e.Category != "PE" || !e.Description.Contains("Elevated entropy")),
    "Descriptive entropy enrichment must remain descriptive-only (ScoreDelta=0).");

try { Directory.Delete(peTestDir2, recursive: true); } catch (Exception) { /* temp cleanup - ignore if already removed */ }
    }
}
