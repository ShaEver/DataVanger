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

// Phase 09 decomposition — Real-Time File Protection (Phase 2 / Step 03). Filter: ~Realtime.
// Faithful move of the legacy mega-[Fact] section into an independently
// runnable, filterable [Fact]. Body is verbatim; the private Assert shim
// delegates to LegacyAssert.True so condition AND message are preserved.
public class RealtimeProtectionTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public async Task RealtimeFileProtection_AllLegacyChecks()
// 26. Real-Time File Protection (Phase 2 / Step 03) — deterministic, development-safe
//     tests for the user-mode file event pipeline. None of these tests may require
//     admin, monitor the repository root, install a service, or leave background
//     work behind. Fake watcher + fake clock drive the orchestrator step-by-step.
{
    static DataVanger.Shared.Realtime.RealtimeWatchProfile DevProfile(string name, string path) =>
        new()
        {
            Name = name,
            Path = path,
            Enabled = true,
            IncludeSubdirectories = false,
            DevelopmentSafe = true,
        };

    static (
        DataVanger.Service.Realtime.RealtimeProtectionService service,
        DataVanger.Infrastructure.FileSystem.FakeFileSystemWatcherFactory factory,
        DataVanger.Infrastructure.Runtime.FakeRuntimeClock clock,
        DataVanger.Service.Protection.InMemoryRealtimeProtectionEventSink sink,
        DataVanger.Engine.Realtime.InMemoryRealtimeScanCache cache,
        ScanRecorder recorder
        ) NewHarness(
        DataVanger.Shared.Realtime.RealtimeProtectionOptions options,
        Func<DataVanger.Shared.Realtime.RealtimeScanRequest, DataVanger.Shared.Realtime.RealtimeScanResult>? scan = null)
    {
        var clock = new DataVanger.Infrastructure.Runtime.FakeRuntimeClock();
        var factory = new DataVanger.Infrastructure.FileSystem.FakeFileSystemWatcherFactory(clock);
        var probe = new DataVanger.Infrastructure.FileSystem.DefaultFileStabilityProbe(
            timeout: TimeSpan.FromSeconds(2),
            pollInterval: TimeSpan.FromMilliseconds(10));
        var recorder = new ScanRecorder(scan);
        var dispatcher = new DataVanger.Engine.Realtime.DelegatingRealtimeScanDispatcher(
            recorder.ScanAsync,
            () => clock.UtcNow);
        var cache = new DataVanger.Engine.Realtime.InMemoryRealtimeScanCache(
            options.ScanCacheLifetime, options.ScanCacheMaxEntries, () => clock.UtcNow);
        var decisionEngine = new DataVanger.Engine.Realtime.ConservativeRealtimeDecisionEngine(() => clock.UtcNow);
        var sink = new DataVanger.Service.Protection.InMemoryRealtimeProtectionEventSink();
        var service = new DataVanger.Service.Realtime.RealtimeProtectionService(
            options, factory, probe, dispatcher, cache, decisionEngine, sink, clock);
        return (service, factory, clock, sink, cache, recorder);
    }

    // 26a. Disabled mode starts no watchers and no scans.
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "datavanger-rtp-disabled-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var options = new DataVanger.Shared.Realtime.RealtimeProtectionOptions
            {
                Enabled = false,
                DevelopmentMode = true,
                PassiveMode = true,
                WatchProfiles = new[] { DevProfile("Disabled", tempDir) },
            };
            var h = NewHarness(options);
            using var svc = h.service;
            await svc.StartAsync(CancellationToken.None);
            var snap = svc.GetStatusSnapshot();
            Assert(!snap.Enabled, "Disabled mode must report Enabled=false.");
            Assert(snap.State == "Disabled", "Disabled mode must surface State=Disabled.");
            Assert(snap.ActiveWatchers == 0, "Disabled mode must not start any watchers.");
            Assert(h.factory.Watchers.Count == 0, "Disabled mode must not create watcher instances.");
            await svc.StopAsync(CancellationToken.None);
        }
        finally { try { Directory.Delete(tempDir, true); } catch (Exception) { /* temp cleanup - ignore if already removed */ } }
    }

    // 26b. Passive mode scans and reports but never authorizes quarantine.
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "datavanger-rtp-passive-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var options = new DataVanger.Shared.Realtime.RealtimeProtectionOptions
            {
                Enabled = true,
                DevelopmentMode = true,
                PassiveMode = true,
                AllowAutomaticQuarantineForConfirmedMalware = true, // even with opt-in: passive wins
                DebounceWindow = TimeSpan.FromMilliseconds(100),
                WatchProfiles = new[] { DevProfile("Downloads", tempDir) },
            };
            var h = NewHarness(options, req => new DataVanger.Shared.Realtime.RealtimeScanResult
            {
                Path = req.Path,
                Verdict = DataVanger.Shared.Realtime.RealtimeProtectionVerdict.ConfirmedMalware,
                IsConfirmedMalware = true,
                CompletedAtUtc = req.EnqueuedAtUtc,
            });
            using var svc = h.service;
            await svc.StartAsync(CancellationToken.None);
            var snap = svc.GetStatusSnapshot();
            Assert(snap.ActiveWatchers == 1, "Passive mode must start watchers normally.");

            var file = Path.Combine(tempDir, "x.exe");
            File.WriteAllBytes(file, new byte[] { (byte)'M', (byte)'Z' });
            var watcher = h.factory.Get("Downloads");
            Assert(watcher != null, "Fake watcher must exist for Downloads profile.");
            watcher!.Raise(DataVanger.Shared.Realtime.RealtimeFileEventKind.Created, file);

            // Step the clock past the debounce window and process one tick.
            h.clock.Advance(TimeSpan.FromMilliseconds(150));
            await svc.ProcessOnceAsync(CancellationToken.None);

            var decisions = h.sink.Snapshot().Where(e => e.Kind == DataVanger.Shared.Realtime.RealtimeProtectionEventKind.DecisionMade).ToList();
            Assert(decisions.Count == 1, "Passive scan must produce exactly one decision event.");
            var dec = decisions[0];
            Assert(dec.Verdict == DataVanger.Shared.Realtime.RealtimeProtectionVerdict.ConfirmedMalware,
                "Decision verdict must mirror the dispatcher verdict.");
            Assert(dec.ActionAuthorized == false,
                "Passive mode must NEVER authorize automatic quarantine, even with explicit opt-in.");
            await svc.StopAsync(CancellationToken.None);
        }
        finally { try { Directory.Delete(tempDir, true); } catch (Exception) { /* temp cleanup - ignore if already removed */ } }
    }

    // 26c. Watch profile with missing directory degrades gracefully.
    {
        var missing = Path.Combine(Path.GetTempPath(), "datavanger-rtp-missing-" + Guid.NewGuid().ToString("N"));
        var options = new DataVanger.Shared.Realtime.RealtimeProtectionOptions
        {
            Enabled = true,
            DevelopmentMode = true,
            PassiveMode = true,
            WatchProfiles = new[] { DevProfile("Ghost", missing) },
        };
        var h = NewHarness(options);
        using var svc = h.service;
        await svc.StartAsync(CancellationToken.None);
        var snap = svc.GetStatusSnapshot();
        Assert(snap.ActiveWatchers == 0, "Missing directory must not produce active watchers.");
        Assert(snap.DegradedWatchers == 1, "Missing directory must be reported as a degraded watcher.");
        Assert(snap.State == "Degraded", "Service must enter Degraded when all profiles are unavailable.");
        Assert(h.sink.Snapshot().Any(e => e.Kind == DataVanger.Shared.Realtime.RealtimeProtectionEventKind.WatchProfileDegraded),
            "Missing-directory degradation must publish a WatchProfileDegraded event.");
        await svc.StopAsync(CancellationToken.None);
    }

    // 26d. Watcher errors become warnings/status events, not crashes.
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "datavanger-rtp-errors-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var options = new DataVanger.Shared.Realtime.RealtimeProtectionOptions
            {
                Enabled = true,
                DevelopmentMode = true,
                PassiveMode = true,
                WatchProfiles = new[] { DevProfile("Err", tempDir) },
            };
            var h = NewHarness(options);
            using var svc = h.service;
            await svc.StartAsync(CancellationToken.None);
            h.factory.Get("Err")!.RaiseError("synthetic native error");
            var snap = svc.GetStatusSnapshot();
            Assert(snap.Warnings >= 1, "Watcher errors must increment the warnings counter.");
            Assert(h.sink.Snapshot().Any(e => e.Kind == DataVanger.Shared.Realtime.RealtimeProtectionEventKind.WatcherError),
                "Watcher errors must publish a WatcherError event.");
            await svc.StopAsync(CancellationToken.None);
        }
        finally { try { Directory.Delete(tempDir, true); } catch (Exception) { /* temp cleanup - ignore if already removed */ } }
    }

    // 26e. Debouncer coalesces rapid same-path events into one scan request.
    {
        var t0 = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var clock = new DataVanger.Infrastructure.Runtime.FakeRuntimeClock(t0);
        var debouncer = new DataVanger.Service.Realtime.RealtimeEventDebouncer(
            TimeSpan.FromMilliseconds(500),
            () => clock.UtcNow);
        for (int i = 0; i < 5; i++)
        {
            debouncer.Submit(new DataVanger.Shared.Realtime.RealtimeFileEvent
            {
                Kind = DataVanger.Shared.Realtime.RealtimeFileEventKind.Changed,
                Path = @"C:\downloads\a.exe",
                TimestampUtc = clock.UtcNow,
                SourceProfile = "Downloads",
            });
            clock.Advance(TimeSpan.FromMilliseconds(50));
        }
        Assert(debouncer.PendingCount == 1, "Five same-path events must coalesce into one pending entry.");
        var earlyDrain = debouncer.Drain();
        Assert(earlyDrain.Count == 0, "Drain before debounce window expires must return nothing.");
        clock.Advance(TimeSpan.FromMilliseconds(500));
        var lateDrain = debouncer.Drain();
        Assert(lateDrain.Count == 1, "Drain after the window must surface exactly one event.");
        Assert(debouncer.PendingCount == 0, "Drained entries must be removed from the pending set.");
    }

    // 26f. Rename moves debouncer entry from old path to new path.
    {
        var clock = new DataVanger.Infrastructure.Runtime.FakeRuntimeClock();
        var debouncer = new DataVanger.Service.Realtime.RealtimeEventDebouncer(
            TimeSpan.FromMilliseconds(100), () => clock.UtcNow);
        debouncer.Submit(new DataVanger.Shared.Realtime.RealtimeFileEvent
        {
            Kind = DataVanger.Shared.Realtime.RealtimeFileEventKind.Created,
            Path = @"C:\downloads\old.exe",
            TimestampUtc = clock.UtcNow,
            SourceProfile = "Downloads",
        });
        Assert(debouncer.PendingCount == 1, "Initial Created must enqueue one entry.");
        debouncer.Submit(new DataVanger.Shared.Realtime.RealtimeFileEvent
        {
            Kind = DataVanger.Shared.Realtime.RealtimeFileEventKind.Renamed,
            Path = @"C:\downloads\new.exe",
            OldPath = @"C:\downloads\old.exe",
            TimestampUtc = clock.UtcNow,
            SourceProfile = "Downloads",
        });
        Assert(debouncer.PendingCount == 1, "Rename must coalesce old path into new path, not double-count.");
        clock.Advance(TimeSpan.FromMilliseconds(200));
        var drained = debouncer.Drain();
        Assert(drained.Count == 1 && drained[0].Path == @"C:\downloads\new.exe",
            "Drained entry must carry the NEW path after a rename.");
    }

    // 26g. Delete cancels any pending scan for that path.
    {
        var clock = new DataVanger.Infrastructure.Runtime.FakeRuntimeClock();
        var debouncer = new DataVanger.Service.Realtime.RealtimeEventDebouncer(
            TimeSpan.FromMilliseconds(100), () => clock.UtcNow);
        debouncer.Submit(new DataVanger.Shared.Realtime.RealtimeFileEvent
        {
            Kind = DataVanger.Shared.Realtime.RealtimeFileEventKind.Created,
            Path = @"C:\downloads\transient.exe",
            TimestampUtc = clock.UtcNow,
            SourceProfile = "Downloads",
        });
        debouncer.Submit(new DataVanger.Shared.Realtime.RealtimeFileEvent
        {
            Kind = DataVanger.Shared.Realtime.RealtimeFileEventKind.Deleted,
            Path = @"C:\downloads\transient.exe",
            TimestampUtc = clock.UtcNow,
            SourceProfile = "Downloads",
        });
        Assert(debouncer.PendingCount == 0,
            "Delete must cancel any pending scan for the same path — never scan a deleted file.");
    }

    // 26h. Eligibility filter — development-mode exclusions and extension policy.
    {
        var opts = new DataVanger.Shared.Realtime.RealtimeProtectionOptions
        {
            Enabled = true,
            DevelopmentMode = true,
        };
        var filter = new DataVanger.Service.Realtime.RealtimeEligibilityFilter(opts);
        var profile = DevProfile("DevProfile", Path.GetTempPath());

        string sep = Path.DirectorySeparatorChar.ToString();
        var binPath = $"C:{sep}repo{sep}bin{sep}Debug{sep}app.exe";
        Assert(!filter.TryAccept(new DataVanger.Shared.Realtime.RealtimeFileEvent
        {
            Kind = DataVanger.Shared.Realtime.RealtimeFileEventKind.Created,
            Path = binPath,
            SourceProfile = "DevProfile",
        }, profile, out _), "Development mode must exclude bin/ paths.");

        var objPath = $"C:{sep}repo{sep}obj{sep}Debug{sep}cache.dll";
        Assert(!filter.TryAccept(new DataVanger.Shared.Realtime.RealtimeFileEvent
        {
            Kind = DataVanger.Shared.Realtime.RealtimeFileEventKind.Created,
            Path = objPath,
            SourceProfile = "DevProfile",
        }, profile, out _), "Development mode must exclude obj/ paths.");

        var gitPath = $"C:{sep}repo{sep}.git{sep}HEAD";
        Assert(!filter.TryAccept(new DataVanger.Shared.Realtime.RealtimeFileEvent
        {
            Kind = DataVanger.Shared.Realtime.RealtimeFileEventKind.Created,
            Path = gitPath,
            SourceProfile = "DevProfile",
        }, profile, out _), "Development mode must exclude .git/ paths.");

        var vsPath = $"C:{sep}repo{sep}.vs{sep}cfg.txt";
        Assert(!filter.TryAccept(new DataVanger.Shared.Realtime.RealtimeFileEvent
        {
            Kind = DataVanger.Shared.Realtime.RealtimeFileEventKind.Created,
            Path = vsPath,
            SourceProfile = "DevProfile",
        }, profile, out _), "Development mode must exclude .vs/ paths.");

        var goodPath = $"C:{sep}downloads{sep}installer.exe";
        Assert(filter.TryAccept(new DataVanger.Shared.Realtime.RealtimeFileEvent
        {
            Kind = DataVanger.Shared.Realtime.RealtimeFileEventKind.Created,
            Path = goodPath,
            SourceProfile = "DevProfile",
        }, profile, out _), ".exe files outside dev folders must be accepted.");

        var mediaPath = $"C:{sep}downloads{sep}video.mp4";
        Assert(!filter.TryAccept(new DataVanger.Shared.Realtime.RealtimeFileEvent
        {
            Kind = DataVanger.Shared.Realtime.RealtimeFileEventKind.Created,
            Path = mediaPath,
            SourceProfile = "DevProfile",
        }, profile, out _), "Default include list must NOT contain .mp4 — large media files are skipped.");

        // Deleted events must always be rejected.
        Assert(!filter.TryAccept(new DataVanger.Shared.Realtime.RealtimeFileEvent
        {
            Kind = DataVanger.Shared.Realtime.RealtimeFileEventKind.Deleted,
            Path = goodPath,
            SourceProfile = "DevProfile",
        }, profile, out _), "Deleted events must never be eligible for scanning.");
    }

    // 26i. Queue overflow produces a warning event and is bounded.
    {
        var q = new DataVanger.Service.Realtime.RealtimeScanQueue(maxLength: 2);
        Assert(q.TryEnqueue(new DataVanger.Shared.Realtime.RealtimeScanRequest { Path = @"C:\a.exe", FileLength = 1 }),
            "First enqueue must succeed.");
        Assert(q.TryEnqueue(new DataVanger.Shared.Realtime.RealtimeScanRequest { Path = @"C:\b.exe", FileLength = 1 }),
            "Second enqueue must succeed.");
        Assert(!q.TryEnqueue(new DataVanger.Shared.Realtime.RealtimeScanRequest { Path = @"C:\c.exe", FileLength = 1 }),
            "Third enqueue must fail (queue bounded at 2).");
        Assert(q.Count == 2, "Queue must remain bounded at capacity.");

        // Coalescing: re-enqueueing the same path replaces, never grows.
        Assert(q.TryEnqueue(new DataVanger.Shared.Realtime.RealtimeScanRequest { Path = @"C:\a.exe", FileLength = 2 }),
            "Coalescing same-path enqueue must succeed.");
        Assert(q.Count == 2, "Coalesced enqueue must not grow the queue.");

        // FIFO dequeue
        Assert(q.TryDequeue(out var r1) && r1!.Path == @"C:\b.exe",
            "Dequeue must surface the older non-coalesced entry first.");
        Assert(q.TryDequeue(out var r2) && r2!.Path == @"C:\a.exe" && r2.FileLength == 2,
            "Coalesced entry must surface the latest values.");
        Assert(!q.TryDequeue(out _), "Empty queue must report no work.");
    }

    // 26j. Cancellation stops the worker loop cleanly without leftovers.
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "datavanger-rtp-cancel-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var options = new DataVanger.Shared.Realtime.RealtimeProtectionOptions
            {
                Enabled = true,
                DevelopmentMode = true,
                PassiveMode = true,
                WatchProfiles = new[] { DevProfile("Cancel", tempDir) },
            };
            var h = NewHarness(options);
            using var svc = h.service;
            await svc.StartAsync(CancellationToken.None);

            using var cts = new CancellationTokenSource();
            cts.Cancel();
            bool threw = false;
            try { await svc.ProcessOnceAsync(cts.Token); }
            catch (OperationCanceledException) { threw = true; }
            Assert(threw, "ProcessOnceAsync must honor a pre-cancelled token.");
            await svc.StopAsync(CancellationToken.None);
            var snap = svc.GetStatusSnapshot();
            Assert(snap.State == "Stopped", "Cancellation followed by Stop must reach Stopped state.");
        }
        finally { try { Directory.Delete(tempDir, true); } catch (Exception) { /* temp cleanup - ignore if already removed */ } }
    }

    // 26k. Scan cache suppresses duplicate scans for unchanged files and
    //      invalidates when length / timestamp change.
    {
        var clock = new DataVanger.Infrastructure.Runtime.FakeRuntimeClock();
        var cache = new DataVanger.Engine.Realtime.InMemoryRealtimeScanCache(
            TimeSpan.FromMinutes(1), maxEntries: 8, () => clock.UtcNow);
        var req = new DataVanger.Shared.Realtime.RealtimeScanRequest
        {
            Path = @"C:\downloads\probe.exe",
            FileLength = 1024,
            LastWriteUtc = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
        };
        var result = new DataVanger.Shared.Realtime.RealtimeScanResult
        {
            Path = req.Path,
            Verdict = DataVanger.Shared.Realtime.RealtimeProtectionVerdict.Clean,
            CompletedAtUtc = clock.UtcNow,
        };
        cache.Store(req, result);
        Assert(cache.TryGet(req, out var hit) && hit is not null && hit.FromCache,
            "Cache must return a hit (FromCache=true) for the same request.");

        // Changed length => miss.
        var changed = new DataVanger.Shared.Realtime.RealtimeScanRequest
        {
            Path = req.Path,
            FileLength = 2048,
            LastWriteUtc = req.LastWriteUtc,
        };
        Assert(!cache.TryGet(changed, out _),
            "Length change must invalidate the cache entry (force re-scan).");

        // Failed results must not be cached.
        var failed = new DataVanger.Shared.Realtime.RealtimeScanResult
        {
            Path = req.Path,
            Verdict = DataVanger.Shared.Realtime.RealtimeProtectionVerdict.Indeterminate,
            Failed = true,
            CompletedAtUtc = clock.UtcNow,
        };
        var freshReq = new DataVanger.Shared.Realtime.RealtimeScanRequest
        {
            Path = @"C:\downloads\fail.exe", FileLength = 1, LastWriteUtc = clock.UtcNow,
        };
        cache.Store(freshReq, failed);
        Assert(!cache.TryGet(freshReq, out _),
            "Failed scan results must NEVER be cached — re-scan next time.");
    }

    // 26l. Anti-FP — heuristic-only realtime result NEVER becomes ConfirmedMalware,
    //      and ConfirmedMalware quarantine is only authorized with explicit opt-in.
    {
        var clock = new DataVanger.Infrastructure.Runtime.FakeRuntimeClock();
        var decisionEngine = new DataVanger.Engine.Realtime.ConservativeRealtimeDecisionEngine(() => clock.UtcNow);

        // Heuristic-only HighRisk -> RecommendManualReview, not authorized.
        var heuristic = new DataVanger.Shared.Realtime.RealtimeScanResult
        {
            Path = @"C:\downloads\heuristic.exe",
            Verdict = DataVanger.Shared.Realtime.RealtimeProtectionVerdict.HighRisk,
            IsConfirmedMalware = false,
            CompletedAtUtc = clock.UtcNow,
        };
        var passiveOpts = new DataVanger.Shared.Realtime.RealtimeProtectionOptions
        {
            Enabled = true, PassiveMode = true, AllowAutomaticQuarantineForConfirmedMalware = true,
        };
        var dec1 = decisionEngine.Decide(heuristic, passiveOpts);
        Assert(dec1.Verdict == DataVanger.Shared.Realtime.RealtimeProtectionVerdict.HighRisk,
            "Heuristic verdict must remain HighRisk; never escalate to ConfirmedMalware.");
        Assert(dec1.RecommendedAction == DataVanger.Shared.Realtime.RealtimeProtectionAction.RecommendManualReview,
            "Heuristic HighRisk must recommend manual review, not quarantine.");
        Assert(!dec1.ActionAuthorized,
            "Heuristic evidence must NEVER authorize automatic action.");

        // ConfirmedMalware with passive mode => recommend but not authorize.
        var confirmedPassive = new DataVanger.Shared.Realtime.RealtimeScanResult
        {
            Path = @"C:\downloads\bad.exe",
            Verdict = DataVanger.Shared.Realtime.RealtimeProtectionVerdict.ConfirmedMalware,
            IsConfirmedMalware = true,
            CompletedAtUtc = clock.UtcNow,
        };
        var dec2 = decisionEngine.Decide(confirmedPassive, passiveOpts);
        Assert(dec2.RecommendedAction == DataVanger.Shared.Realtime.RealtimeProtectionAction.QuarantineConfirmedMalware,
            "Confirmed malware must recommend quarantine.");
        Assert(!dec2.ActionAuthorized,
            "Passive mode must NEVER authorize automatic quarantine.");

        // ConfirmedMalware with active mode + opt-in => authorized.
        var activeOpts = new DataVanger.Shared.Realtime.RealtimeProtectionOptions
        {
            Enabled = true, PassiveMode = false, AllowAutomaticQuarantineForConfirmedMalware = true,
        };
        var dec3 = decisionEngine.Decide(confirmedPassive, activeOpts);
        Assert(dec3.ActionAuthorized,
            "Active mode + explicit opt-in must authorize automatic quarantine for ConfirmedMalware.");

        // ConfirmedMalware with active mode but NO opt-in => not authorized.
        var noOptInOpts = new DataVanger.Shared.Realtime.RealtimeProtectionOptions
        {
            Enabled = true, PassiveMode = false, AllowAutomaticQuarantineForConfirmedMalware = false,
        };
        var dec4 = decisionEngine.Decide(confirmedPassive, noOptInOpts);
        Assert(!dec4.ActionAuthorized,
            "Without explicit AllowAutomaticQuarantine opt-in, ConfirmedMalware must NOT be auto-actioned.");

        // ConfirmedMalware verdict but IsConfirmedMalware=false (defensive belt-and-braces).
        var inconsistent = new DataVanger.Shared.Realtime.RealtimeScanResult
        {
            Path = @"C:\downloads\inconsistent.exe",
            Verdict = DataVanger.Shared.Realtime.RealtimeProtectionVerdict.ConfirmedMalware,
            IsConfirmedMalware = false,
            CompletedAtUtc = clock.UtcNow,
        };
        var dec5 = decisionEngine.Decide(inconsistent, activeOpts);
        Assert(!dec5.ActionAuthorized && dec5.RecommendedAction != DataVanger.Shared.Realtime.RealtimeProtectionAction.QuarantineConfirmedMalware,
            "Inconsistent ConfirmedMalware (verdict says so but flag false) must NOT authorize automatic action.");

        // Failed scan -> ObserveOnly, never authorized, never confirmed.
        var failed = new DataVanger.Shared.Realtime.RealtimeScanResult
        {
            Path = @"C:\downloads\failed.exe",
            Verdict = DataVanger.Shared.Realtime.RealtimeProtectionVerdict.Indeterminate,
            Failed = true,
            FailureReason = "engine unavailable",
            CompletedAtUtc = clock.UtcNow,
        };
        var dec6 = decisionEngine.Decide(failed, activeOpts);
        Assert(dec6.RecommendedAction == DataVanger.Shared.Realtime.RealtimeProtectionAction.ObserveOnly && !dec6.ActionAuthorized,
            "Failed scan must observe only, NEVER become a malware verdict.");
    }

    // 26m. DelegatingRealtimeScanDispatcher converts thrown exceptions to Failed results,
    //      never to malware verdicts.
    {
        var clock = new DataVanger.Infrastructure.Runtime.FakeRuntimeClock();
        var dispatcher = new DataVanger.Engine.Realtime.DelegatingRealtimeScanDispatcher(
            (_, _) => throw new InvalidOperationException("synthetic scan failure"),
            () => clock.UtcNow);
        var req = new DataVanger.Shared.Realtime.RealtimeScanRequest
        {
            Path = @"C:\downloads\boom.exe", FileLength = 1, LastWriteUtc = clock.UtcNow,
        };
        var res = await dispatcher.DispatchAsync(req, CancellationToken.None);
        Assert(res.Failed && res.Verdict == DataVanger.Shared.Realtime.RealtimeProtectionVerdict.Indeterminate,
            "Dispatcher must convert exceptions to Failed/Indeterminate, never to malware.");
        Assert(!res.IsConfirmedMalware,
            "Exceptions from the scan delegate must NEVER be promoted to ConfirmedMalware.");
    }

    // 26n. Dispatcher refuses to honor IsConfirmedMalware unless verdict agrees.
    {
        var dispatcher = new DataVanger.Engine.Realtime.DelegatingRealtimeScanDispatcher(
            (req, _) => Task.FromResult(new DataVanger.Shared.Realtime.RealtimeScanResult
            {
                Path = req.Path,
                Verdict = DataVanger.Shared.Realtime.RealtimeProtectionVerdict.HighRisk,
                IsConfirmedMalware = true, // tries to bypass anti-FP
                CompletedAtUtc = DateTimeOffset.UtcNow,
            }));
        var req = new DataVanger.Shared.Realtime.RealtimeScanRequest
        {
            Path = @"C:\downloads\bypass.exe", FileLength = 1, LastWriteUtc = DateTimeOffset.UtcNow,
        };
        var res = await dispatcher.DispatchAsync(req, CancellationToken.None);
        Assert(!res.IsConfirmedMalware,
            "Dispatcher must clear IsConfirmedMalware when the verdict is not ConfirmedMalware (anti-FP belt-and-braces).");
    }

    // 26o. End-to-end: orchestrator -> dispatcher -> decision via cache hit on second pass.
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "datavanger-rtp-e2e-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var options = new DataVanger.Shared.Realtime.RealtimeProtectionOptions
            {
                Enabled = true,
                DevelopmentMode = true,
                PassiveMode = true,
                DebounceWindow = TimeSpan.FromMilliseconds(50),
                MaxConcurrentScans = 1,
                WatchProfiles = new[] { DevProfile("E2E", tempDir) },
            };
            var h = NewHarness(options, req => new DataVanger.Shared.Realtime.RealtimeScanResult
            {
                Path = req.Path,
                Verdict = DataVanger.Shared.Realtime.RealtimeProtectionVerdict.Clean,
                CompletedAtUtc = req.EnqueuedAtUtc,
            });
            using var svc = h.service;
            await svc.StartAsync(CancellationToken.None);
            var file = Path.Combine(tempDir, "doc.pdf");
            File.WriteAllText(file, "%PDF-1.0\nbody");
            var watcher = h.factory.Get("E2E")!;
            watcher.Raise(DataVanger.Shared.Realtime.RealtimeFileEventKind.Created, file);
            h.clock.Advance(TimeSpan.FromMilliseconds(75));
            await svc.ProcessOnceAsync(CancellationToken.None);
            int firstScanCount = h.recorder.ScanCount;
            Assert(firstScanCount == 1, "First scan must hit the dispatcher exactly once.");

            // Re-trigger same file without changing it — cache should suppress.
            watcher.Raise(DataVanger.Shared.Realtime.RealtimeFileEventKind.Changed, file);
            h.clock.Advance(TimeSpan.FromMilliseconds(75));
            await svc.ProcessOnceAsync(CancellationToken.None);
            Assert(h.recorder.ScanCount == firstScanCount,
                "Cache must suppress a re-scan when length+timestamp are unchanged.");
            var snap = svc.GetStatusSnapshot();
            Assert(snap.DuplicatesSuppressed >= 1, "Suppressed duplicate must be reflected in status counters.");
            await svc.StopAsync(CancellationToken.None);
        }
        finally { try { Directory.Delete(tempDir, true); } catch (Exception) { /* temp cleanup - ignore if already removed */ } }
    }

    // 26p. Lifecycle is free of background work: many start/stop cycles complete quickly.
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "datavanger-rtp-life-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            for (int i = 0; i < 20; i++)
            {
                var options = new DataVanger.Shared.Realtime.RealtimeProtectionOptions
                {
                    Enabled = true,
                    DevelopmentMode = true,
                    PassiveMode = true,
                    DebounceWindow = TimeSpan.FromMilliseconds(50),
                    WatchProfiles = new[] { DevProfile("LifeCycle", tempDir) },
                };
                var h = NewHarness(options);
                using var svc = h.service;
                await svc.StartAsync(CancellationToken.None);
                await svc.StopAsync(CancellationToken.None);
            }
            sw.Stop();
            Assert(sw.ElapsedMilliseconds < 2000,
                $"RealtimeProtectionService lifecycle must be free of background work (took {sw.ElapsedMilliseconds}ms).");
        }
        finally { try { Directory.Delete(tempDir, true); } catch (Exception) { /* temp cleanup - ignore if already removed */ } }
    }

    // 26q. Disposed service never resurrects.
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "datavanger-rtp-dispose-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var options = new DataVanger.Shared.Realtime.RealtimeProtectionOptions
            {
                Enabled = true,
                DevelopmentMode = true,
                PassiveMode = true,
                WatchProfiles = new[] { DevProfile("Dispose", tempDir) },
            };
            var h = NewHarness(options);
            var svc = h.service;
            await svc.StartAsync(CancellationToken.None);
            svc.Dispose();
            await svc.StartAsync(CancellationToken.None);
            var snap = svc.GetStatusSnapshot();
            Assert(snap.State == "Stopped",
                "Disposed service must remain Stopped after a subsequent StartAsync.");
        }
        finally { try { Directory.Delete(tempDir, true); } catch (Exception) { /* temp cleanup - ignore if already removed */ } }
    }

    // 26r. Stability probe: non-existent path => NotFound (never throws).
    {
        // Use the real clock here so wall-clock timeout actually fires
        // (Task.Delay is wall-clock and the probe must terminate).
        var probe = new DataVanger.Infrastructure.FileSystem.DefaultFileStabilityProbe(
            TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(10));
        var missing = Path.Combine(Path.GetTempPath(), "datavanger-stability-ghost-" + Guid.NewGuid().ToString("N"));
        var probeResult = await probe.ProbeAsync(missing, 1024, CancellationToken.None);
        Assert(probeResult.Outcome == DataVanger.Infrastructure.FileSystem.FileStabilityOutcome.NotFound,
            "Stability probe on a missing path must report NotFound.");

        // Directory path => IsDirectory
        var probeDir = await probe.ProbeAsync(Path.GetTempPath(), 1024, CancellationToken.None);
        Assert(probeDir.Outcome == DataVanger.Infrastructure.FileSystem.FileStabilityOutcome.IsDirectory,
            "Stability probe on a directory must report IsDirectory.");
    }

    // 26s. Stability probe: oversized file => TooLarge, with metadata captured.
    {
        var tempFile = Path.Combine(Path.GetTempPath(), "datavanger-stability-large-" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(tempFile, new byte[1024]);
        try
        {
            var probe = new DataVanger.Infrastructure.FileSystem.DefaultFileStabilityProbe(
                TimeSpan.FromMilliseconds(200), TimeSpan.FromMilliseconds(10));
            var res = await probe.ProbeAsync(tempFile, maxSizeBytes: 128, CancellationToken.None);
            Assert(res.Outcome == DataVanger.Infrastructure.FileSystem.FileStabilityOutcome.TooLarge,
                "Stability probe must classify oversized files as TooLarge.");
            Assert(res.Length == 1024,
                "Oversized result must still report the observed length.");
        }
        finally { try { File.Delete(tempFile); } catch (Exception) { /* temp cleanup - ignore if already removed */ } }
    }
}

}
