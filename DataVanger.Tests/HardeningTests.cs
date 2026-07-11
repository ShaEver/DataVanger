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

// Phase 09 decomposition — Testing, Performance & Hardening (caps, cancellation, resilience). Filter: ~Hardening.
// Faithful move of the legacy mega-[Fact] section into an independently
// runnable, filterable [Fact]. Body is verbatim; the private Assert shim
// delegates to LegacyAssert.True so condition AND message are preserved.
public class HardeningTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public void TestingPerformanceHardening_AllLegacyChecks()
// 23. Testing, Performance & Hardening — regression coverage, resource caps,
//     cancellation/timeout safety, corrupted-input resilience.
// ============================================================================
{
    // -- 23a. DeepScanProfileSettings exposes a non-zero MaxFindings ceiling on
    //         every shipped profile so a runaway scan can never grow the result
    //         list without bound.
    foreach (var p in new[] { ScanProfile.Fast, ScanProfile.Deep, ScanProfile.Deep, ScanProfile.Deep })
    {
        var s = DataVanger.Engine.DeepScan.DeepScanProfileSettings.Resolve(p, new AppSettings(), new ScanOptions { Profile = p });
        Assert(s.MaxFindings > 0,
            $"DeepScanProfileSettings({p}) must expose a positive MaxFindings cap.");
        Assert(s.MaxFindings >= 1_000,
            $"DeepScanProfileSettings({p}) MaxFindings must be high enough to avoid clamping real scans.");
    }

    // -- 23b. DeepScanContext.AddFinding stops growing once MaxFindings is hit;
    //         excess findings are counted and dropped, never added.
    {
        var capProfile = new DataVanger.Engine.DeepScan.DeepScanProfileSettings
        {
            Profile = ScanProfile.Deep,
            MaxArchiveDepth = 0,
            MaxArchiveEntries = 0,
            MaxTotalDecompressedBytes = 0,
            MaxCompressionRatio = 100,
            MaxNestedArchives = 0,
            MaxFileBytes = 0,
            MaxInMemoryEntryBytes = 0,
            MaxDegreeOfParallelism = 1,
            CpuThrottleDelayMs = 0,
            WorkQueueCapacity = 4,
            MaxFindings = 3,
            PerFileTimeout = TimeSpan.FromSeconds(1),
            PerArchiveTimeout = TimeSpan.FromSeconds(1),
            PerHashTimeout = TimeSpan.FromSeconds(1),
            OverallTimeout = TimeSpan.FromSeconds(5),
        };
        var scanCtx = new ScanContext(new ScanOptions { Profile = ScanProfile.Deep }, new AppSettings(),
            Array.Empty<string>(), Array.Empty<string>(), "");
        var telem = new DataVanger.Engine.DeepScan.DeepScanTelemetry();
        using var throttle = new DataVanger.Engine.DeepScan.ScanThrottle(1, 0);
        var ch = System.Threading.Channels.Channel.CreateBounded<DataVanger.Engine.DeepScan.ScanWorkItem>(4);
        var logger = new DataVanger.Infrastructure.DelegateScanLogger(_ => { });
        var modules = new DataVanger.Engine.DetectionModuleRegistry(Array.Empty<DataVanger.Core.Abstractions.IDetectionModule>());
        var pending = new DataVanger.Engine.DeepScan.PendingWorkCounter();
        var ctx = new DataVanger.Engine.DeepScan.DeepScanContext(
            capProfile, scanCtx, telem, throttle, ch.Writer, modules, logger, pending);

        DataVanger.Engine.DeepScan.ScanWorkItem MakeItem(int i) =>
            new(new DataVanger.Engine.DeepScan.MemoryContentSource(
                    $"item-{i}.bin", new byte[] { (byte)i }, "cap-test"), 0);

        for (int i = 0; i < 10; i++) ctx.AddFinding(MakeItem(i));

        Assert(ctx.Findings.Count == 3,
            "DeepScanContext must stop adding findings once MaxFindings is reached.");
        Assert(ctx.FindingsDroppedCount == 7,
            "DeepScanContext must count the dropped findings, not silently lose them.");

        // null finding is safely ignored — no throw, no counter increment.
        long before = ctx.FindingsDroppedCount;
        ctx.AddFinding(null!);
        Assert(ctx.Findings.Count == 3 && ctx.FindingsDroppedCount == before,
            "DeepScanContext.AddFinding(null) must be a safe no-op.");

        // MaxFindings == 0 means unlimited (legacy behavior preserved).
        var unlimitedProfile = new DataVanger.Engine.DeepScan.DeepScanProfileSettings
        {
            Profile = ScanProfile.Deep,
            MaxArchiveDepth = 0,
            MaxArchiveEntries = 0,
            MaxTotalDecompressedBytes = 0,
            MaxCompressionRatio = 100,
            MaxNestedArchives = 0,
            MaxFileBytes = 0,
            MaxInMemoryEntryBytes = 0,
            MaxDegreeOfParallelism = 1,
            CpuThrottleDelayMs = 0,
            WorkQueueCapacity = 4,
            MaxFindings = 0,
            PerFileTimeout = TimeSpan.FromSeconds(1),
            PerArchiveTimeout = TimeSpan.FromSeconds(1),
            PerHashTimeout = TimeSpan.FromSeconds(1),
            OverallTimeout = TimeSpan.FromSeconds(5),
        };
        var ctx2 = new DataVanger.Engine.DeepScan.DeepScanContext(
            unlimitedProfile, scanCtx, telem, throttle, ch.Writer, modules, logger, pending);
        for (int i = 0; i < 50; i++) ctx2.AddFinding(MakeItem(i));
        Assert(ctx2.Findings.Count == 50 && ctx2.FindingsDroppedCount == 0,
            "DeepScanContext with MaxFindings=0 must preserve legacy unlimited behavior.");
    }

    // -- 23c. ZipBombGuard edge cases: zero/negative reservations, ratio
    //         overflow, streamed-byte budget.
    {
        var bombA = new DataVanger.Engine.DeepScan.ZipBombGuard(maxTotalDecompressedBytes: 1024, maxEntries: 4, maxCompressionRatio: 10);

        Assert(bombA.TryAdmit(0, 0).Allowed,
            "ZipBombGuard must safely admit zero-byte entries without dividing by zero.");
        Assert(bombA.TryAdmit(-1, -1).Allowed,
            "ZipBombGuard must clamp negative reported sizes to safe defaults.");
        Assert(bombA.TryAdmit(50, 5).Allowed,
            "Compression ratio exactly at the cap must be admitted.");
        var bombDecision = bombA.TryAdmit(1000, 1);
        Assert(!bombDecision.Allowed && bombDecision.Reason == DataVanger.Engine.DeepScan.ZipBombReason.RatioExceeded,
            "ZipBombGuard must reject entries whose compression ratio exceeds the cap.");
        Assert(bombA.EntriesInspected >= 4, "Entries counter must reflect every admission attempt.");
        var bombTooMany = bombA.TryAdmit(1, 1);
        Assert(!bombTooMany.Allowed && bombTooMany.Reason == DataVanger.Engine.DeepScan.ZipBombReason.TooManyEntries,
            "ZipBombGuard must reject the 5th entry once MaxEntries=4 is exhausted.");

        // Decompressed byte budget enforcement does not corrupt the counter on
        // rejection (the reservation is rolled back).
        var bombB = new DataVanger.Engine.DeepScan.ZipBombGuard(maxTotalDecompressedBytes: 100, maxEntries: 100, maxCompressionRatio: 1000);
        Assert(bombB.TryAdmit(80, 80).Allowed, "First admission under cap must succeed.");
        Assert(!bombB.TryAdmit(50, 50).Allowed, "Second admission that breaches the cap must be rejected.");
        Assert(bombB.DecompressedBytes == 80,
            "ZipBombGuard must roll back the byte reservation when the cap was breached.");
        Assert(bombB.TryAdmit(20, 20).Allowed,
            "An admission that fits exactly into the remaining budget must succeed.");

        // ReportStreamedBytes catches archives that lie about uncompressed size.
        var bombC = new DataVanger.Engine.DeepScan.ZipBombGuard(maxTotalDecompressedBytes: 100, maxEntries: 100, maxCompressionRatio: 1000);
        Assert(bombC.ReportStreamedBytes(50), "Streaming bytes within budget must keep returning true.");
        Assert(bombC.ReportStreamedBytes(0), "Reporting zero bytes is a safe no-op.");
        Assert(bombC.ReportStreamedBytes(-1), "Negative reported bytes are clamped, never break the budget.");
        Assert(!bombC.ReportStreamedBytes(60),
            "Streaming bytes that overflow the cumulative cap must return false.");
    }

    // -- 23d. RecursionGuard nested-archive registration is thread-safe.
    {
        var guard = new DataVanger.Engine.DeepScan.RecursionGuard(maxDepth: 4, maxNestedArchives: 1000);
        int successes = 0;
        int failures = 0;
        Parallel.For(0, 1500, _ =>
        {
            if (guard.TryRegisterNestedArchive()) Interlocked.Increment(ref successes);
            else Interlocked.Increment(ref failures);
        });
        Assert(successes == 1000,
            $"RecursionGuard must admit exactly MaxNestedArchives entries under contention (got {successes}).");
        Assert(failures == 500,
            "RecursionGuard must reject every attempt past the limit, never over-admit.");
        Assert(!guard.DepthAllowed(5), "Depths beyond MaxDepth must be rejected.");
        Assert(guard.DepthAllowed(0) && guard.DepthAllowed(4),
            "Depths within MaxDepth must be accepted.");
        Assert(guard.TryVisit("hash-A") && !guard.TryVisit("hash-A"),
            "RecursionGuard.TryVisit must dedupe identical fingerprints.");
        Assert(guard.TryVisit(""), "Empty fingerprints must always be accepted (no dedupe key).");

        var zeroGuard = new DataVanger.Engine.DeepScan.RecursionGuard(0, 0);
        Assert(!zeroGuard.TryRegisterNestedArchive(),
            "RecursionGuard with zero nested-archive budget must reject every attempt.");
    }

    // -- 23e. RuntimeTelemetryThrottle drops floods deterministically and
    //         keeps the bucket dictionary bounded under stress.
    {
        var th = new DataVanger.Runtime.RuntimeTelemetryThrottle(maxPerWindow: 5, window: TimeSpan.FromMinutes(1));
        var ts = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
        int allowed = 0, dropped = 0;
        for (int i = 0; i < 20; i++)
        {
            var ev = new DataVanger.Runtime.RuntimeTelemetryEvent(
                kind: DataVanger.Runtime.RuntimeTelemetryEventKind.ProcessStart,
                providerName: "test", pid: 100, parentPid: 1,
                processName: "p", imagePath: "", commandLine: "", scriptContent: null,
                extraTag: "", timestampUtc: ts);
            if (th.ShouldAllow(ev)) allowed++; else dropped++;
        }
        Assert(allowed == 5 && dropped == 15,
            $"RuntimeTelemetryThrottle must allow exactly MaxPerWindow events per (kind,pid) per window (allowed={allowed}, dropped={dropped}).");
        Assert(th.AllowedCount == 5 && th.DroppedCount == 15,
            "Throttle counters must agree with the observed allow/drop split.");

        // Different pid gets its own bucket.
        var other = new DataVanger.Runtime.RuntimeTelemetryEvent(
            DataVanger.Runtime.RuntimeTelemetryEventKind.ProcessStart, "test", 200, 1,
            "p", "", "", null, "", ts);
        Assert(th.ShouldAllow(other),
            "RuntimeTelemetryThrottle must isolate per-pid buckets.");

        // Null event is safely rejected.
        Assert(!th.ShouldAllow(null!),
            "RuntimeTelemetryThrottle must reject null events without throwing.");

        // Pruning keeps the dictionary bounded.
        var bigTh = new DataVanger.Runtime.RuntimeTelemetryThrottle(maxPerWindow: 1, window: TimeSpan.FromMinutes(1));
        var baseTs = new DateTime(2026, 2, 1, 0, 0, 0, DateTimeKind.Utc);
        for (int i = 0; i < 2000; i++)
        {
            bigTh.ShouldAllow(new DataVanger.Runtime.RuntimeTelemetryEvent(
                DataVanger.Runtime.RuntimeTelemetryEventKind.ProcessStart,
                "test", i, 1, "p", "", "", null, "", baseTs.AddSeconds(i)));
        }
        int pruned = bigTh.Prune(maxBuckets: 256);
        Assert(pruned >= 1700, $"RuntimeTelemetryThrottle.Prune must reclaim oldest buckets aggressively (pruned={pruned}).");
    }

    // -- 23f. InMemoryEtwProvider — start/stop semantics, dispose, exception
    //         isolation. Confirms the runtime degrades gracefully without ETW.
    {
        using var prov = new DataVanger.Runtime.Etw.InMemoryEtwProvider();
        Assert(!prov.IsRunning, "Provider must start in the not-running state.");
        Assert(!prov.EmitProcessStart(1, 0, "p", "", ""),
            "Emit before Start must be a safe no-op.");

        prov.Start();
        Assert(prov.IsRunning, "Provider must report running after Start.");

        int received = 0;
        prov.EventReceived += _ => received++;
        Assert(prov.EmitProcessStart(1, 0, "p", "", ""), "Emit after Start must publish to subscribers.");
        Assert(received == 1, "Single subscriber must receive exactly one event for one Emit.");

        // A throwing subscriber must NOT poison the provider.
        prov.EventReceived += _ => throw new InvalidOperationException("rude subscriber");
        bool stillOk = prov.EmitImageLoad(1, "p", @"C:\Windows\System32\kernel32.dll");
        Assert(stillOk, "InMemoryEtwProvider must isolate subscriber exceptions; subsequent Emits must keep working.");

        prov.Stop();
        Assert(!prov.IsRunning, "Provider must report stopped after Stop.");
        Assert(!prov.EmitProcessEnd(1, "p"),
            "Emit after Stop must be a safe no-op.");

        // Dispose is idempotent.
        prov.Dispose();
        prov.Dispose();
    }

    // -- 23g. InMemoryAmsiProvider — graceful handling of empty / whitespace
    //         input, exception isolation, and benign-script-no-event contract.
    {
        using var amsi = new DataVanger.Runtime.Amsi.InMemoryAmsiProvider();
        amsi.Start();
        int events = 0;
        amsi.EventReceived += _ => events++;

        Assert(amsi.SubmitContent("test", "", 100) == 0,
            "AMSI must publish no events for empty content.");
        Assert(amsi.SubmitContent("test", "   \t\n", 100) == 0,
            "AMSI must publish no events for whitespace-only content.");
        Assert(amsi.SubmitContent("test", "Write-Output 'hello'", 100) == 0,
            "AMSI must not produce events for benign scripts.");

        // Suspicious script: should at least emit an event (don't pin the kind,
        // just confirm we got telemetry).
        int suspiciousPublished = amsi.SubmitContent("test",
            "powershell -EncodedCommand " + new string('A', 600), 100);
        Assert(suspiciousPublished >= 1,
            "AMSI must surface suspicious encoded payloads as runtime telemetry.");

        // After Stop the provider must be inert.
        amsi.Stop();
        Assert(amsi.SubmitContent("test", "Invoke-Expression 'evil'", 100) == 0,
            "AMSI must publish no events after Stop.");
    }

    // -- 23h. BehavioralEventBus drops the OLDEST event under flood, never the
    //         newest, and keeps memory bounded. Subscriber exceptions must not
    //         crash the bus.
    {
        using var bus = new DataVanger.Behavioral.BehavioralEventBus(capacity: 16);
        int seen = 0;
        var lastDescriptions = new List<string>();
        using (bus.Subscribe(ev => { seen++; lastDescriptions.Add(ev.Description); }))
        {
            // Throwing subscriber must not poison the bus.
            using (bus.Subscribe(_ => throw new InvalidOperationException("rude")))
            {
                var baseTs = new DateTime(2026, 3, 1, 0, 0, 0, DateTimeKind.Utc);
                for (int i = 0; i < 1000; i++)
                {
                    bus.Publish(new DataVanger.Behavioral.BehavioralEvent(
                        kind: DataVanger.Behavioral.BehavioralEventKind.ProcessStart,
                        pid: i, parentPid: 1, processName: "p", imagePath: "",
                        commandLine: "", targetPath: "", extraTag: "",
                        severity: DataVanger.Behavioral.BehavioralSeverity.Low,
                        description: "evt-" + i, timestampUtc: baseTs.AddMilliseconds(i)));
                }
                bus.DrainNow();
            }
        }
        Assert(bus.CurrentQueueSize == 0, "Bus must be drained after DrainNow.");
        Assert(bus.DroppedCount > 0,
            "BehavioralEventBus must drop the OLDEST events when the publisher floods past capacity.");
        Assert(bus.PublishedCount == 1000,
            "PublishedCount must reflect every publish attempt, including those whose backing slot was later overwritten.");
        // The healthy subscriber kept running through the rude one.
        Assert(seen > 0, "Healthy subscribers must keep receiving events even when another subscriber throws.");
    }

    // -- 23i. ResilientFileSystemService — cancellation, access-denied
    //         callback wiring, and depth limit.
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "dv-fs-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);
        try
        {
            // Build a small tree:  root/a/b/c with one file at every level.
            File.WriteAllText(Path.Combine(tempRoot, "root.txt"), "x");
            string a = Path.Combine(tempRoot, "a");      Directory.CreateDirectory(a);
            File.WriteAllText(Path.Combine(a, "a.txt"), "x");
            string b = Path.Combine(a, "b");             Directory.CreateDirectory(b);
            File.WriteAllText(Path.Combine(b, "b.txt"), "x");
            string c = Path.Combine(b, "c");             Directory.CreateDirectory(c);
            File.WriteAllText(Path.Combine(c, "c.txt"), "x");

            var fs = new DataVanger.Infrastructure.ResilientFileSystemService();

            // Unbounded walk: every file is returned.
            var all = fs.EnumerateFiles(tempRoot, CancellationToken.None).Select(f => f.Name).OrderBy(n => n).ToList();
            Assert(all.SequenceEqual(new[] { "a.txt", "b.txt", "c.txt", "root.txt" }),
                "ResilientFileSystemService must enumerate every file in the tree.");

            // Depth-1 walk: only root and a-level files reach the consumer.
            var depthLimited = fs.EnumerateFiles(tempRoot, CancellationToken.None, onAccessDenied: null, maxDepth: 1)
                .Select(f => f.Name).OrderBy(n => n).ToList();
            Assert(!depthLimited.Contains("b.txt") && !depthLimited.Contains("c.txt"),
                "ResilientFileSystemService(maxDepth:1) must not descend into level-2 subdirectories.");
            Assert(depthLimited.Contains("root.txt") && depthLimited.Contains("a.txt"),
                "ResilientFileSystemService(maxDepth:1) must still surface level-0 and level-1 files.");

            // Cancellation stops enumeration promptly.
            using var ctsFs = new CancellationTokenSource();
            ctsFs.Cancel();
            var cancelledRows = fs.EnumerateFiles(tempRoot, ctsFs.Token).ToList();
            Assert(cancelledRows.Count == 0,
                "ResilientFileSystemService must surface no files when cancellation is already requested.");

            // Bad root: yields no files, never throws.
            var missing = fs.EnumerateFiles(Path.Combine(tempRoot, "does-not-exist"), CancellationToken.None).ToList();
            Assert(missing.Count == 0,
                "ResilientFileSystemService must tolerate missing roots without throwing.");
        }
        finally
        {
            try { Directory.Delete(tempRoot, recursive: true); } catch (Exception) { /* temp cleanup - ignore if already removed */ }
        }
    }

    // -- 23j. ForensicReportExporter — HTML timeline truncation when far over
    //         the rendering cap; XSS hygiene for evidence-chain node strings;
    //         empty report still produces a valid HTML document.
    {
        var exporter = new DataVanger.Reporting.Forensics.ForensicReportExporter();

        // Build a synthetic report that exceeds the HTML cap. We bypass the
        // builder so we can stuff the timeline cheaply and keep the test deterministic.
        var ts0 = new DateTime(2026, 4, 1, 0, 0, 0, DateTimeKind.Utc);
        var timeline = new DataVanger.Reporting.Forensics.ForensicTimeline();
        int target = DataVanger.Reporting.Forensics.ForensicReportExporter.MaxHtmlTimelineEvents + 10;
        for (int i = 0; i < target; i++)
        {
            timeline.Add(new DataVanger.Reporting.Forensics.TimelineEvent(
                timestampUtc: ts0.AddSeconds(i),
                sourceModule: "Synthetic",
                category: "noise",
                description: "evt-" + i,
                processId: 0,
                processName: "",
                severity: DataVanger.Reporting.Forensics.ForensicSeverity.Informational,
                correlationId: ""));
        }
        var meta = new DataVanger.Reporting.Forensics.ForensicReportMetadata
        {
            ReportId = "rpt",
            ScanId = "scan",
            EngineVersion = "test",
            Profile = ScanProfile.Deep,
            ScanStartedUtc = ts0,
            ScanCompletedUtc = ts0.AddSeconds(target),
            HostName = "host",
        };
        var summary = new DataVanger.Reporting.Forensics.ForensicReportSummary();
        var hugeReport = new DataVanger.Reporting.Forensics.ForensicReport(
            metadata: meta, summary: summary,
            incidents: Array.Empty<DataVanger.Reporting.Forensics.Incident>(),
            evidenceChains: Array.Empty<DataVanger.Reporting.Forensics.EvidenceChain>(),
            timeline: timeline);

        string html = exporter.RenderHtml(hugeReport);
        Assert(html.Contains("eventos omitidos") || html.Contains("[+ "),
            "RenderHtml must mark the timeline as truncated once it exceeds MaxHtmlTimelineEvents.");
        Assert(!html.Contains("evt-" + (target - 1)),
            "RenderHtml must not include the trailing events that exceed the cap.");

        // Empty report still renders into a valid document.
        var emptyReport = new DataVanger.Reporting.Forensics.ForensicReportBuilder().Build(
            new DataVanger.Reporting.Forensics.ForensicReportInput());
        string emptyHtml = exporter.RenderHtml(emptyReport);
        Assert(emptyHtml.StartsWith("<!DOCTYPE html>") && emptyHtml.Contains("Nenhum incidente"),
            "RenderHtml(empty) must produce a valid HTML document with the no-incident notice.");
        string emptyJson = exporter.SerializeJson(emptyReport);
        Assert(emptyJson.Contains("\"incidents\":") && emptyJson.Contains("[]"),
            "SerializeJson(empty) must emit an empty incidents array, never crash.");

        // XSS hygiene: a node description with a script tag must not be rendered raw.
        var xssChain = new DataVanger.Reporting.Forensics.EvidenceChain(
            targetId: @"C:\evil\<script>alert(1)</script>.exe",
            subject: "<img src=x onerror=alert(2)>",
            nodes: new[]
            {
                new DataVanger.Reporting.Forensics.EvidenceChainNode(
                    sourceModule: "Heur",
                    category: "Heuristic",
                    description: "<script>alert('XSS')</script>",
                    scoreDelta: 1,
                    strength: EvidenceStrength.Medium,
                    canConfirmMalware: false,
                    timestampUtc: ts0),
            });
        var xssIncident = new DataVanger.Reporting.Forensics.Incident(
            id: "i1", title: "<svg/onload=alert(3)>",
            severity: DataVanger.Reporting.Forensics.ForensicSeverity.High,
            confidence: DataVanger.Reporting.Forensics.ForensicConfidence.High,
            chains: new[] { xssChain },
            timeline: Array.Empty<DataVanger.Reporting.Forensics.TimelineEvent>(),
            mitigationNotes: Array.Empty<string>());
        var xssReport = new DataVanger.Reporting.Forensics.ForensicReport(
            metadata: meta, summary: summary,
            incidents: new[] { xssIncident },
            evidenceChains: new[] { xssChain },
            timeline: new DataVanger.Reporting.Forensics.ForensicTimeline());
        string xssHtml = exporter.RenderHtml(xssReport);
        Assert(!xssHtml.Contains("<script>alert('XSS')</script>"),
            "RenderHtml must HTML-escape script tags from evidence node descriptions.");
        Assert(!xssHtml.Contains("<svg/onload=alert(3)>"),
            "RenderHtml must HTML-escape svg/onload payloads from incident titles.");
    }

    // -- 23k. IncidentAggregator caps incident buckets at MaxIncidentBuckets
    //         so a million-chain scan cannot blow up the report.
    {
        var agg = new DataVanger.Reporting.Forensics.IncidentAggregator();
        var lots = new List<DataVanger.Reporting.Forensics.EvidenceChain>();
        int n = DataVanger.Reporting.Forensics.IncidentAggregator.MaxIncidentBuckets + 50;
        for (int i = 0; i < n; i++)
        {
            lots.Add(new DataVanger.Reporting.Forensics.EvidenceChain(
                targetId: "target-" + i,
                subject: "subj-" + i,
                nodes: new[] { new DataVanger.Reporting.Forensics.EvidenceChainNode(
                    sourceModule: "Synthetic", category: "noise", description: "x",
                    scoreDelta: 0, strength: EvidenceStrength.Medium,
                    canConfirmMalware: false,
                    timestampUtc: new DateTime(2026,1,1,0,0,0,DateTimeKind.Utc)) }));
        }
        var incidents = agg.Aggregate(lots);
        Assert(incidents.Count <= DataVanger.Reporting.Forensics.IncidentAggregator.MaxIncidentBuckets + 1,
            "IncidentAggregator must not grow past MaxIncidentBuckets (plus the dedicated overflow bucket).");
        // No chain is silently dropped: total chains preserved across all incidents.
        int totalChains = incidents.Sum(i => i.Chains.Count);
        Assert(totalChains == n,
            "IncidentAggregator must preserve every input chain, funneling overflow into the spillover bucket.");

        // Null input is safely tolerated.
        var safeEmpty = agg.Aggregate(null!);
        Assert(safeEmpty.Count == 0,
            "IncidentAggregator must return an empty list when fed a null sequence, never throw.");

        // Cap does not apply when chains naturally cluster (e.g. shared TargetId).
        var clustered = new List<DataVanger.Reporting.Forensics.EvidenceChain>();
        for (int i = 0; i < 200; i++)
        {
            clustered.Add(new DataVanger.Reporting.Forensics.EvidenceChain(
                targetId: "single",
                subject: "subj",
                nodes: new[] { new DataVanger.Reporting.Forensics.EvidenceChainNode(
                    sourceModule: "Synthetic", category: "noise", description: "x",
                    scoreDelta: 0, strength: EvidenceStrength.Medium,
                    canConfirmMalware: false,
                    timestampUtc: new DateTime(2026,1,1,0,0,0,DateTimeKind.Utc)) }));
        }
        var clusteredInc = agg.Aggregate(clustered);
        Assert(clusteredInc.Count == 1,
            "Chains sharing TargetId must merge into a single incident, regardless of count.");
    }

    // -- 23l. Anti-FP regression: large fan-out of heuristic-only evidence must
    //         still never produce a ConfirmedMalware incident in the report.
    {
        var findings = new List<ScanFinding>();
        for (int i = 0; i < 5_000; i++)
        {
            var f = new ScanFinding
            {
                Path = $@"C:\Users\Test\AppData\Roaming\heur{i}.exe",
                Score = RiskThresholds.Critical + 30,
            };
            f.Evidence.Add(new Evidence
            {
                Category = "Heuristic",
                Description = "Auto-suspect: " + i,
                ScoreDelta = 10,
                Strength = EvidenceStrength.High,
                CanConfirmMalware = false,
            });
            findings.Add(f);
        }
        var report = new DataVanger.Reporting.Forensics.ForensicReportBuilder().Build(
            new DataVanger.Reporting.Forensics.ForensicReportInput { Findings = findings });
        Assert(report.Incidents.All(i => i.Severity != DataVanger.Reporting.Forensics.ForensicSeverity.ConfirmedMalware),
            "Even thousands of heuristic-only findings must never produce a ConfirmedMalware incident (anti-FP).");
        Assert(report.Summary.HighestSeverity != DataVanger.Reporting.Forensics.ForensicSeverity.ConfirmedMalware,
            "Report-summary highest severity must stay below ConfirmedMalware when no confirmed evidence exists.");
    }

    // -- 23m. ThreatClassificationPolicy regression: a high-score finding with
    //         only low/medium-strength evidence (no blacklist, no confirmed
    //         signature) must NEVER flip to ConfirmedMalware regardless of how
    //         high the score climbs. Guards the anti-FP contract for the
    //         classifier surface directly.
    {
        var finding = new ScanFinding
        {
            Path = @"C:\Users\Test\Downloads\maybe.exe",
            Score = RiskThresholds.Critical + 100,
            HasConfirmedSignature = false,
            IsBlacklisted = false,
        };
        finding.Evidence.Add(new Evidence
        {
            Category = "Heuristic",
            Description = "Low-strength heuristic",
            ScoreDelta = 5,
            Strength = EvidenceStrength.Low,
            CanConfirmMalware = false,
        });
        Assert(ThreatClassificationPolicy.Classify(finding) != ThreatClass.ConfirmedMalware,
            "A score above Critical with only low-strength heuristic evidence must never confirm malware.");
        Assert(!ThreatClassificationPolicy.AllowsAutomaticAction(finding),
            "Same finding must not unlock automatic action.");
    }

    // -- 23n. CommandLineAnalyzer regression — encoded / hidden / dynamic
    //         signals must keep firing after this hardening pass. Guards
    //         the anti-regression warning in the task brief.
    {
        var enc = DataVanger.Behavioral.Monitors.CommandLineAnalyzer.Analyze(
            "powershell.exe", J("powershell.exe -EncodedCommand ", new string('A', 200)));
        Assert(enc.Tags.Contains("encoded-payload"),
            "CommandLineAnalyzer must keep flagging -EncodedCommand invocations.");

        var hidden = DataVanger.Behavioral.Monitors.CommandLineAnalyzer.Analyze(
            "powershell.exe", J("powershell.exe -windowstyle hidden -nop -c \"echo hi\""));
        Assert(hidden.Tags.Contains("hidden-execution"),
            "CommandLineAnalyzer must keep flagging -windowstyle hidden invocations.");

        var dyn = DataVanger.Behavioral.Monitors.CommandLineAnalyzer.Analyze(
            "powershell.exe", J("powershell.exe -c \"Invoke-Expression $env:DATA\""));
        Assert(dyn.Tags.Contains("dynamic-execution"),
            "CommandLineAnalyzer must keep flagging Invoke-Expression / dynamic execution.");

        // Benign command must produce no suspicious tags — guards against
        // over-eager regex tightening introducing false positives.
        var benign = DataVanger.Behavioral.Monitors.CommandLineAnalyzer.Analyze(
            "powershell.exe", "powershell.exe -NoProfile -Command Get-Date");
        Assert(!benign.Tags.Contains("encoded-payload")
            && !benign.Tags.Contains("hidden-execution")
            && !benign.Tags.Contains("dynamic-execution"),
            "CommandLineAnalyzer must not flag benign PowerShell invocations.");
    }

    // -- 23o. ThrowingMemoryRule must not crash the test fixture surface;
    //         confirms our throwing-rule fixture itself behaves safely so
    //         section 20's degradation tests stay deterministic.
    {
        DataVanger.Memory.Rules.IMemoryRule rule = new ThrowingMemoryRule();
        Assert(!rule.RequiresBytes,
            "ThrowingMemoryRule fixture must declare RequiresBytes=false.");
        bool threw = false;
        try
        {
            rule.Evaluate(
                process: new DataVanger.Memory.ProcessSnapshot(
                    processId: 1, processName: "test", imagePath: "",
                    isAccessible: true, isSystemProtected: false),
                region: new DataVanger.Memory.MemoryRegion(
                    processId: 1,
                    baseAddress: 0x1000, size: 4096,
                    protection: DataVanger.Memory.MemoryProtection.Read,
                    kind: DataVanger.Memory.MemoryRegionKind.Private,
                    backingPath: null),
                sampleBytes: Array.Empty<byte>(),
                cancellationToken: CancellationToken.None);
        }
        catch (InvalidOperationException) { threw = true; }
        Assert(threw,
            "ThrowingMemoryRule fixture must surface the failure to the engine, which catches it as graceful degradation.");
    }

    // -- 23p. Cancellation safety: a CTS that is cancelled before work is
    //         enqueued must not let an enumerator block. We use the existing
    //         FS service since it accepts CancellationToken directly.
    {
        var fs = new DataVanger.Infrastructure.ResilientFileSystemService();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var rows = fs.EnumerateFiles(Path.GetTempPath(), cts.Token).Take(1).ToList();
        sw.Stop();
        Assert(sw.ElapsedMilliseconds < 1000,
            $"Cancelled enumeration must return promptly (took {sw.ElapsedMilliseconds}ms).");
    }
}

// ============================================================================
}
