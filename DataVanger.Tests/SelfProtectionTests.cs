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

// Phase 09 decomposition — Self-Protection (tamper evidence, integrity, watchdog, anti-FP). Filter: ~SelfProtection.
// Faithful move of the legacy mega-[Fact] section into an independently
// runnable, filterable [Fact]. Body is verbatim; the private Assert shim
// delegates to LegacyAssert.True so condition AND message are preserved.
public class SelfProtectionTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public void SelfProtection_AllLegacyChecks()
// 24. Self-Protection — tamper evidence, integrity validation, watchdog,
//     development-mode safety, anti-FP contract.
// ============================================================================
{
    // -- 24a. Default policy is development-safe.
    {
        var policy = DataVanger.SelfProtection.SelfProtectionPolicy.DevelopmentDefault();
        Assert(policy.Mode == DataVanger.SelfProtection.SelfProtectionMode.Development,
            "SelfProtectionPolicy.DevelopmentDefault must run in Development mode.");
        Assert(policy.Level != DataVanger.SelfProtection.SelfProtectionLevel.Off,
            "Default development policy must still enable a basic protection level.");
        Assert(policy.MaxWatchdogAttempts > 0,
            "MaxWatchdogAttempts must be positive to allow at least one recovery attempt.");
    }

    // -- 24b. SelfProtectionLevel.Off => manager transitions to Disabled
    //         and is a no-op for all subsequent calls.
    {
        var policy = new DataVanger.SelfProtection.SelfProtectionPolicy
        {
            Level = DataVanger.SelfProtection.SelfProtectionLevel.Off,
            Mode = DataVanger.SelfProtection.SelfProtectionMode.Production,
        };
        using var mgr = new DataVanger.SelfProtection.SelfProtectionManager(policy);
        var state = mgr.Start();
        Assert(state == DataVanger.SelfProtection.SelfProtectionState.Disabled,
            "Off level must produce Disabled state.");
        mgr.ReportServiceStopAttempt("svc", "test");
        Assert(mgr.TamperHistory.PublishedCount == 0,
            "Disabled manager must not publish any tamper events.");
    }

    // -- 24c. Development mode is the safe default state when the level
    //         is non-Off.
    {
        using var mgr = new DataVanger.SelfProtection.SelfProtectionManager();
        Assert(mgr.Start() == DataVanger.SelfProtection.SelfProtectionState.DevelopmentMode,
            "Default manager must start in DevelopmentMode.");
        Assert(mgr.Start() == DataVanger.SelfProtection.SelfProtectionState.DevelopmentMode,
            "Start() must be idempotent — calling it twice keeps the same state.");
    }

    // -- 24d. InMemoryTamperEventSink is bounded and drops the OLDEST
    //         events under flooding.
    {
        var sink = new DataVanger.SelfProtection.InMemoryTamperEventSink(capacity: 4);
        var baseTs = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
        for (int i = 0; i < 10; i++)
        {
            sink.Publish(new DataVanger.SelfProtection.TamperEvent(
                DataVanger.SelfProtection.TamperKind.ConfigurationModified,
                DataVanger.SelfProtection.TamperSeverity.Low,
                "config", $"path-{i}", "x", baseTs.AddSeconds(i)));
        }
        var snap = sink.Snapshot();
        Assert(snap.Count == 4,
            $"InMemoryTamperEventSink must cap retained events at Capacity (got {snap.Count}).");
        Assert(sink.PublishedCount == 10 && sink.DroppedCount == 6,
            "PublishedCount/DroppedCount must agree with the observed admission split.");
        Assert(snap[0].TargetPath == "path-6" && snap[3].TargetPath == "path-9",
            "InMemoryTamperEventSink must drop the OLDEST events, never the newest.");
        Assert(!sink.Publish(null!),
            "Publish(null) must be a safe no-op.");
        sink.Dispose();
        Assert(!sink.Publish(new DataVanger.SelfProtection.TamperEvent(
            DataVanger.SelfProtection.TamperKind.ConfigurationModified,
            DataVanger.SelfProtection.TamperSeverity.Low, "c", "p", "d", baseTs)),
            "Disposed sink must reject new events.");
    }

    // -- 24e. Sha256IntegrityValidator detects mismatches and missing
    //         files deterministically using in-memory overrides.
    {
        var contents = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["alpha.bin"] = new byte[] { 1, 2, 3 },
            ["beta.bin"]  = new byte[] { 4, 5, 6 },
            // "gamma.bin" is intentionally absent to exercise the "missing" path.
        };
        byte[]? Read(string p) => contents.TryGetValue(p, out var b) ? b : null;
        var validator = new DataVanger.SelfProtection.Sha256IntegrityValidator(Read);

        string alphaHash = validator.ComputeSha256("alpha.bin") ?? "";
        string betaHash  = validator.ComputeSha256("beta.bin")  ?? "";
        Assert(alphaHash.Length == 64 && betaHash.Length == 64,
            "Sha256IntegrityValidator.ComputeSha256 must return a 64-char hex hash.");

        var baseline = new DataVanger.SelfProtection.IntegritySnapshot(new[]
        {
            new KeyValuePair<string,string>("alpha.bin", alphaHash),
            new KeyValuePair<string,string>("beta.bin",  "DEADBEEF"), // intentionally wrong
            new KeyValuePair<string,string>("gamma.bin", alphaHash),  // intentionally missing
        });
        var result = validator.Validate(baseline);
        Assert(result.Matched.Count == 1 && result.Matched[0] == "alpha.bin",
            "Sha256IntegrityValidator must report alpha.bin as matched.");
        Assert(result.Mismatched.Count == 1 && result.Mismatched[0].Path == "beta.bin",
            "Sha256IntegrityValidator must report beta.bin as mismatched.");
        Assert(result.Missing.Count == 1 && result.Missing[0] == "gamma.bin",
            "Sha256IntegrityValidator must report gamma.bin as missing.");
        Assert(!result.IsClean,
            "Result with mismatches/missing must report IsClean=false.");

        // Empty snapshot returns Empty result without throwing.
        Assert(validator.Validate(DataVanger.SelfProtection.IntegritySnapshot.Empty).CheckedCount == 0,
            "Empty snapshot must yield an empty validation result.");
    }

    // -- 24f. ConfigurationIntegrityMonitor publishes tamper events for
    //         mismatched/missing entries; clean baseline emits nothing.
    {
        var bytes = new byte[] { 9, 9, 9 };
        var goodHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
        var sink = new DataVanger.SelfProtection.InMemoryTamperEventSink();
        var validator = new DataVanger.SelfProtection.Sha256IntegrityValidator(_ => bytes);

        // Clean baseline: no events.
        var cleanSnapshot = new DataVanger.SelfProtection.IntegritySnapshot(new[]
        {
            new KeyValuePair<string,string>("config.json", goodHash),
        });
        var monitor = new DataVanger.SelfProtection.ConfigurationIntegrityMonitor(cleanSnapshot, sink, validator);
        var cleanResult = monitor.Verify();
        Assert(cleanResult.IsClean && sink.PublishedCount == 0,
            "ConfigurationIntegrityMonitor must not publish events when the baseline matches.");

        // Tampered baseline: mismatch + missing entries each produce one event.
        var sink2 = new DataVanger.SelfProtection.InMemoryTamperEventSink();
        var validator2 = new DataVanger.SelfProtection.Sha256IntegrityValidator(p =>
            p == "config.json" ? bytes : null);
        var bad = new DataVanger.SelfProtection.IntegritySnapshot(new[]
        {
            new KeyValuePair<string,string>("config.json", "DEADBEEF"),  // mismatch
            new KeyValuePair<string,string>("missing.json", goodHash),    // missing
        });
        var monitor2 = new DataVanger.SelfProtection.ConfigurationIntegrityMonitor(bad, sink2, validator2);
        var ts = new DateTime(2026, 5, 1, 0, 0, 0, DateTimeKind.Utc);
        monitor2.Verify(ts);
        var events = sink2.Snapshot();
        Assert(events.Count == 2,
            "ConfigurationIntegrityMonitor must emit exactly one event per mismatch + missing entry.");
        Assert(events.Any(e => e.Kind == DataVanger.SelfProtection.TamperKind.ConfigurationModified
                               && e.TargetPath == "config.json"),
            "Mismatch must surface as ConfigurationModified.");
        Assert(events.Any(e => e.Kind == DataVanger.SelfProtection.TamperKind.ConfigurationMissing
                               && e.TargetPath == "missing.json"),
            "Missing baseline file must surface as ConfigurationMissing.");
        Assert(events.All(e => e.TimestampUtc == ts),
            "Verify(nowUtc) must stamp emitted events with the supplied timestamp.");
    }

    // -- 24g. Watchdog respects retry budget and cooldown, and never invokes
    //         the recovery callback in development mode.
    {
        var policy = new DataVanger.SelfProtection.SelfProtectionPolicy
        {
            Level = DataVanger.SelfProtection.SelfProtectionLevel.Standard,
            Mode = DataVanger.SelfProtection.SelfProtectionMode.Development,
            MaxWatchdogAttempts = 2,
            WatchdogCooldown = TimeSpan.FromSeconds(10),
        };
        var sink = new DataVanger.SelfProtection.InMemoryTamperEventSink();
        var watchdog = new DataVanger.SelfProtection.Watchdog(policy, sink);
        int recoveryInvocations = 0;
        watchdog.Register("svc", healthCheck: () => false, recovery: () => Interlocked.Increment(ref recoveryInvocations));

        var t0 = new DateTime(2026, 5, 1, 12, 0, 0, DateTimeKind.Utc);
        var obs1 = watchdog.Observe("svc", t0);
        Assert(obs1.Outcome == DataVanger.SelfProtection.WatchdogOutcome.RecoveryAttempted
               && obs1.AttemptCount == 1,
            "First unhealthy observation must record a RecoveryAttempted outcome.");
        Assert(recoveryInvocations == 0,
            "Development mode must NEVER invoke the recovery callback.");

        // Inside cooldown.
        var obs2 = watchdog.Observe("svc", t0.AddSeconds(1));
        Assert(obs2.Outcome == DataVanger.SelfProtection.WatchdogOutcome.OnCooldown,
            "Second observation within the cooldown window must be OnCooldown.");

        // Past cooldown -> second attempt.
        var obs3 = watchdog.Observe("svc", t0.AddSeconds(30));
        Assert(obs3.Outcome == DataVanger.SelfProtection.WatchdogOutcome.RecoveryAttempted
               && obs3.AttemptCount == 2,
            "Past cooldown the watchdog must record a second attempt.");

        // Past cooldown again -> retry budget exhausted -> GaveUp.
        var obs4 = watchdog.Observe("svc", t0.AddSeconds(60));
        Assert(obs4.Outcome == DataVanger.SelfProtection.WatchdogOutcome.GaveUp,
            "Past MaxWatchdogAttempts the watchdog must give up.");
        Assert(sink.Snapshot().Any(e => e.Kind == DataVanger.SelfProtection.TamperKind.WatchdogGaveUp),
            "Watchdog must publish a WatchdogGaveUp tamper event when the retry budget is exhausted.");
    }

    // -- 24h. Production-mode watchdog invokes the recovery callback,
    //         but a throwing callback is swallowed without crashing.
    {
        var policy = new DataVanger.SelfProtection.SelfProtectionPolicy
        {
            Level = DataVanger.SelfProtection.SelfProtectionLevel.Standard,
            Mode = DataVanger.SelfProtection.SelfProtectionMode.Production,
            MaxWatchdogAttempts = 3,
            WatchdogCooldown = TimeSpan.FromSeconds(5),
        };
        var watchdog = new DataVanger.SelfProtection.Watchdog(policy);
        int invocations = 0;
        watchdog.Register("alpha", () => false, () => Interlocked.Increment(ref invocations));
        watchdog.Register("throwy", () => false, () => throw new InvalidOperationException("synthetic"));

        var t0 = new DateTime(2026, 5, 2, 12, 0, 0, DateTimeKind.Utc);
        var alphaObs = watchdog.Observe("alpha", t0);
        Assert(alphaObs.Outcome == DataVanger.SelfProtection.WatchdogOutcome.RecoveryAttempted,
            "Production-mode watchdog must record RecoveryAttempted for unhealthy components.");
        Assert(invocations == 1,
            "Production-mode watchdog must invoke the recovery callback.");

        var throwyObs = watchdog.Observe("throwy", t0);
        Assert(throwyObs.Outcome == DataVanger.SelfProtection.WatchdogOutcome.RecoveryFailed,
            "Throwing recovery callback must yield RecoveryFailed without crashing the watchdog.");
    }

    // -- 24i. Watchdog: healthy component resets attempt counters and is
    //         not registered components emit a benign Healthy observation.
    {
        var policy = DataVanger.SelfProtection.SelfProtectionPolicy.DevelopmentDefault();
        var watchdog = new DataVanger.SelfProtection.Watchdog(policy);
        bool healthy = false;
        watchdog.Register("svc", () => healthy);
        var t0 = new DateTime(2026, 5, 3, 12, 0, 0, DateTimeKind.Utc);
        watchdog.Observe("svc", t0);
        Assert(watchdog.Components.Count == 1,
            "Watchdog.Components must list registered names.");

        healthy = true;
        var ok = watchdog.Observe("svc", t0.AddMinutes(1));
        Assert(ok.Outcome == DataVanger.SelfProtection.WatchdogOutcome.Healthy,
            "Healthy component must yield a Healthy observation.");

        var unknown = watchdog.Observe("nope", t0);
        Assert(unknown.Outcome == DataVanger.SelfProtection.WatchdogOutcome.Healthy
               && unknown.Description.Contains("not registered", StringComparison.OrdinalIgnoreCase),
            "Unregistered component lookup must return a benign Healthy observation, never throw.");
    }

    // -- 24j. BehavioralTamperBridge forwards tamper events as
    //         SecurityTamperIndicator to the BehavioralEventBus and the
    //         behavioral pipeline keeps CanConfirmMalware=false.
    {
        using var bus = new DataVanger.Behavioral.BehavioralEventBus(capacity: 64);
        var received = new List<DataVanger.Behavioral.BehavioralEvent>();
        using var sub = bus.Subscribe(e => { lock (received) received.Add(e); });
        var bridge = new DataVanger.SelfProtection.BehavioralTamperBridge(bus);
        var ts = new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc);
        bridge.Publish(new DataVanger.SelfProtection.TamperEvent(
            DataVanger.SelfProtection.TamperKind.ConfigurationModified,
            DataVanger.SelfProtection.TamperSeverity.High,
            "config", "settings.json", "baseline diverged", ts));
        bus.DrainNow();
        Assert(received.Count == 1 && received[0].Kind == DataVanger.Behavioral.BehavioralEventKind.SecurityTamperIndicator,
            "BehavioralTamperBridge must forward as SecurityTamperIndicator.");
        Assert(received[0].ExtraTag == "self-protection",
            "Bridge must tag forwarded events as 'self-protection'.");
        Assert(received[0].Severity == DataVanger.Behavioral.BehavioralSeverity.High,
            "Severity must map High->High through the bridge.");
        Assert(received[0].TargetPath == "settings.json",
            "Bridge must preserve the tamper target path.");
        Assert(bridge.ForwardedCount == 1 && bridge.DroppedCount == 0,
            "Bridge must update its counters accurately.");

        // null event is a safe no-op.
        Assert(!bridge.Publish(null!),
            "Bridge.Publish(null) must return false without throwing.");
        Assert(bridge.DroppedCount == 1,
            "Bridge must count rejected null events as dropped.");
    }

    // -- 24k. End-to-end: self-protection tamper signals routed through
    //         a BehavioralEngine NEVER produce ConfirmedMalware evidence.
    {
        using var engine = new DataVanger.Behavioral.BehavioralEngine();
        using var mgr = new DataVanger.SelfProtection.SelfProtectionManager(
            DataVanger.SelfProtection.SelfProtectionPolicy.ProductionStandard(),
            engine);
        mgr.Start();
        mgr.ReportServiceStopAttempt("scheduler", "synthetic stop attempt",
            nowUtc: new DateTime(2026, 7, 1, 0, 0, 0, DateTimeKind.Utc));
        engine.DrainNow();

        Assert(mgr.TamperHistory.PublishedCount == 1,
            "Active manager must record the tamper event in its history.");

        // Walk every chain in the correlation engine and confirm no Evidence
        // can confirm malware. The anti-FP contract must hold even when the
        // self-protection bridge is wired up.
        var evidences = engine.Correlation.Snapshot()
            .SelectMany(c => c.Evidence)
            .ToList();
        Assert(evidences.All(e => !e.CanConfirmMalware),
            "Self-protection tamper signals must NEVER yield CanConfirmMalware evidence.");
        Assert(evidences.All(e => e.Strength != EvidenceStrength.Confirmed),
            "Self-protection tamper signals must NEVER reach EvidenceStrength.Confirmed.");
    }

    // -- 24l. RecoveryManager records actions, is bounded, and bridges
    //         a RecoveryActionTaken tamper event for each recording.
    {
        var sink = new DataVanger.SelfProtection.InMemoryTamperEventSink();
        var manager = new DataVanger.SelfProtection.RecoveryManager(sink, capacity: 4);
        for (int i = 0; i < 10; i++)
        {
            manager.Record("config", DataVanger.SelfProtection.RecoveryOutcome.Succeeded,
                $"restored entry {i}");
        }
        Assert(manager.RecordedCount == 10 && manager.DroppedCount == 6,
            "RecoveryManager must cap retained actions at capacity and count drops.");
        Assert(manager.Snapshot().Count == 4,
            "RecoveryManager snapshot must respect capacity.");
        Assert(sink.PublishedCount == 10,
            "RecoveryManager must publish a RecoveryActionTaken tamper event for every recording.");
        var lastEvent = sink.Snapshot().Last();
        Assert(lastEvent.Kind == DataVanger.SelfProtection.TamperKind.RecoveryActionTaken,
            "Recovery actions must surface as RecoveryActionTaken tamper events.");
    }

    // -- 24m. CompositeTamperSink isolates throwing children and still
    //         delivers events to healthy sinks.
    {
        var tamperDiagnostics = new List<string>();
        var good = new DataVanger.SelfProtection.InMemoryTamperEventSink();
        var bad = new ThrowingTamperSink();
        var composite = new DataVanger.SelfProtection.CompositeTamperSink(
            new DataVanger.SelfProtection.ITamperEventSink[] { bad, good },
            diagnostics: tamperDiagnostics.Add);
        var ev = new DataVanger.SelfProtection.TamperEvent(
            DataVanger.SelfProtection.TamperKind.ConfigurationModified,
            DataVanger.SelfProtection.TamperSeverity.Low, "c", "p", "d",
            new DateTime(2026, 8, 1, 0, 0, 0, DateTimeKind.Utc));
        Assert(composite.Publish(ev),
            "CompositeTamperSink must return true when at least one child accepted the event.");
        Assert(good.PublishedCount == 1,
            "Healthy child must still see the event even when a sibling threw.");
        Assert(tamperDiagnostics.Count == 1,
            "Throwing child must produce exactly one diagnostic.");
    }

    // -- 24n. Dispose is idempotent and rejects new events afterwards.
    {
        var mgr = new DataVanger.SelfProtection.SelfProtectionManager();
        mgr.Start();
        mgr.Dispose();
        mgr.Dispose(); // must not throw
        Assert(mgr.State == DataVanger.SelfProtection.SelfProtectionState.Stopped,
            "Dispose must transition the manager to Stopped state.");
        Assert(mgr.Start() == DataVanger.SelfProtection.SelfProtectionState.Stopped,
            "Start after Dispose must remain Stopped — no resurrection.");
    }

    // -- 24o. The default tests run must not require admin / leave any
    //         background threads behind. We assert the manager + watchdog
    //         do not spin up workers — measure by ensuring construction +
    //         disposal completes in well under one second.
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        for (int i = 0; i < 50; i++)
        {
            using var mgr = new DataVanger.SelfProtection.SelfProtectionManager();
            mgr.Start();
            mgr.ReportTelemetryInterruption("etw", "synthetic gap");
            mgr.Stop();
        }
        sw.Stop();
        Assert(sw.ElapsedMilliseconds < 2000,
            $"SelfProtectionManager lifecycle must be free of background work (took {sw.ElapsedMilliseconds}ms).");
    }
}
}
