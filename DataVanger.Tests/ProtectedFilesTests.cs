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

// Phase 09 decomposition — Protected Files Activity Monitor (Phase 2 / Step 07). Filter: ~ProtectedFiles.
// Faithful move of the legacy mega-[Fact] section into an independently
// runnable, filterable [Fact]. Body is verbatim; the private Assert shim
// delegates to LegacyAssert.True so condition AND message are preserved.
public class ProtectedFilesTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public async Task ProtectedFilesActivityMonitor_AllLegacyChecks()
// 30. Protected Files Activity Monitor (Phase 2 / Step 07) — deterministic,
//     development-safe tests. The monitor passively consumes normalized
//     runtime file events (fake/in-memory — never real ETW, never real file
//     I/O), correlates high-volume mutation/rename/extension-transition
//     activity in bounded, TTL-cleaned state, records recovery-protection
//     indicators as normalized metadata LABELS ONLY, and emits protected-file
//     activity evidence that is EVIDENCE ONLY (never ConfirmedMalware, never
//     quarantine/kill/suspend/block/write-block, never recovery commands).
//     No admin, no network, no background loops, no sleeps, no destructive
//     file operations.
{
    var pfaNow = new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero);

    DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent PfaFile(
        DataVanger.Shared.RuntimeEvents.RuntimeEventCategory category,
        string path, int pid = 42, string proc = "evil.exe",
        string? previousPath = null, DataVanger.Shared.RuntimeEvents.RuntimeEventSource? source = null,
        double? entropyAfter = null, double? entropyBefore = null,
        DateTimeOffset? ts = null)
    {
        var meta = new Dictionary<string, string>(StringComparer.Ordinal);
        if (previousPath != null) meta["protectedfiles.previous_path"] = previousPath;
        if (entropyAfter != null) meta["protectedfiles.entropy_after"] =
            entropyAfter.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (entropyBefore != null) meta["protectedfiles.entropy_before"] =
            entropyBefore.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return new DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent
        {
            Source = source ?? DataVanger.Shared.RuntimeEvents.RuntimeEventSource.RealtimeFileProtection,
            Category = category,
            ProcessId = pid,
            ProcessName = proc,
            SubjectPath = path,
            TimestampUtc = ts ?? pfaNow,
            Metadata = meta,
        };
    }

    // 30a. Default options are conservative and development-safe.
    {
        var o = DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityOptions.DevelopmentSafe();
        Assert(o.Mode == DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityMode.Development,
            "Default Protected Files mode must be Development (passive/dev-safe).");
        Assert(!o.EnableEntropySampling, "Entropy sampling must be OFF by default.");
        Assert(!o.EnableActiveResponseHooks, "Active response hooks must be OFF by default.");
        Assert(o.IsEnabled, "Development mode must report enabled.");
    }

    // 30b. Disabled mode generates no evidence and reports Disabled.
    {
        var sink = new CollectingProtectedFilesEvidenceSink();
        using var m = new DataVanger.Engine.ProtectedFiles.ProtectedFilesActivityMonitor(
            DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityOptions.Disabled(),
            pipeline: null, evidenceSink: sink, timeProvider: () => pfaNow);
        await m.StartAsync();
        for (int i = 0; i < 100; i++)
            await m.HandleAsync(PfaFile(DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.FileChanged,
                $@"C:\Users\bob\Documents\f{i}.docx")).AsTask();
        var h = m.GetHealthSnapshot();
        Assert(h.State == DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityMonitorState.Disabled,
            "Disabled monitor must report Disabled state.");
        Assert(!h.IsEnabled, "Disabled monitor must report IsEnabled=false.");
        Assert(h.EvidenceGenerated == 0 && sink.Items.Count == 0,
            "Disabled monitor must generate no activity evidence.");
    }

    // 30c. Passive mode: mass file modification burst creates suspicious
    //      evidence WITHOUT any action; never ConfirmedMalware.
    {
        var sink = new CollectingProtectedFilesEvidenceSink();
        using var m = new DataVanger.Engine.ProtectedFiles.ProtectedFilesActivityMonitor(
            DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityOptions.Passive(),
            pipeline: null, evidenceSink: sink, timeProvider: () => pfaNow);
        await m.StartAsync();
        for (int i = 0; i < 60; i++)
            await m.HandleAsync(PfaFile(DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.FileChanged,
                $@"C:\Users\bob\Documents\f{i}.docx")).AsTask();
        Assert(sink.Items.Count >= 1, "Mass modification burst must create activity evidence.");
        Assert(sink.Items.All(e => !e.IsConfirmedMalware),
            "Protected-file activity evidence must NEVER be ConfirmedMalware.");
        Assert(sink.Items.All(e =>
                e.Severity <= DataVanger.Shared.ProtectedFiles.ProtectedFilesActivitySeverity.ProtectedActivitySuspected),
            "Activity severity must never exceed ProtectedActivitySuspected.");
        var h = m.GetHealthSnapshot();
        Assert(h.State == DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityMonitorState.Passive,
            "Passive() must run in passive state (no actions).");
    }

    // 30d. Development/build paths are NOT scored — dotnet build / bin / obj
    //      activity must never trip the monitor.
    {
        var sink = new CollectingProtectedFilesEvidenceSink();
        using var m = new DataVanger.Engine.ProtectedFiles.ProtectedFilesActivityMonitor(
            DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityOptions.DevelopmentSafe(),
            pipeline: null, evidenceSink: sink, timeProvider: () => pfaNow);
        await m.StartAsync();
        for (int i = 0; i < 500; i++)
            await m.HandleAsync(PfaFile(DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.FileChanged,
                $@"C:\repo\DataVanger\bin\Debug\f{i}.dll", proc: "dotnet")).AsTask();
        Assert(sink.Items.Count == 0,
            "High-volume build/bin activity must produce no evidence (development safety).");
    }

    // 30e. Mass rename burst with suspicious extension transitions in a
    //      protected folder => HighRisk or higher; never ConfirmedMalware.
    {
        var sink = new CollectingProtectedFilesEvidenceSink();
        using var m = new DataVanger.Engine.ProtectedFiles.ProtectedFilesActivityMonitor(
            DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityOptions.Passive(),
            pipeline: null, evidenceSink: sink, timeProvider: () => pfaNow);
        await m.StartAsync();
        for (int i = 0; i < 40; i++)
            await m.HandleAsync(PfaFile(DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.FileRenamed,
                $@"C:\Users\bob\Documents\f{i}.locked", previousPath: $@"C:\Users\bob\Documents\f{i}.docx"))
                .AsTask();
        Assert(sink.Items.Count >= 1, "Mass rename burst must create evidence.");
        var top = sink.Items.OrderByDescending(e => e.Severity).First();
        Assert(top.RenameCount >= 25, "Rename count must be surfaced in evidence.");
        Assert(top.Severity >= DataVanger.Shared.ProtectedFiles.ProtectedFilesActivitySeverity.HighRisk,
            "Rename burst + suspicious extensions + protected folder must be HighRisk or higher.");
        Assert(top.TopExtensionTransitions.Any(t => t.Contains(".docx->.locked")),
            "Top extension transition (.docx->.locked) must be summarized.");
        Assert(sink.Items.All(e => !e.IsConfirmedMalware), "Rename evidence must never be ConfirmedMalware.");
    }

    // 30f. Recovery-protection indicator (normalized metadata LABEL ONLY)
    //      creates Suspicious evidence; the label alone is NOT ConfirmedMalware.
    //      No OS command is ever parsed, reconstructed, emitted, or executed.
    {
        var sink = new CollectingProtectedFilesEvidenceSink();
        using var m = new DataVanger.Engine.ProtectedFiles.ProtectedFilesActivityMonitor(
            DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityOptions.Passive(),
            pipeline: null, evidenceSink: sink, timeProvider: () => pfaNow);
        await m.StartAsync();
        await m.HandleAsync(new DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent
        {
            Category = DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.TamperObserved,
            ProcessId = 77, ProcessName = "evil.exe", TimestampUtc = pfaNow,
            Metadata = new Dictionary<string, string>
            {
                [DataVanger.Engine.ProtectedFiles.RecoveryProtectionIndicators.MetaSingle] =
                    DataVanger.Engine.ProtectedFiles.RecoveryProtectionIndicators.ShadowCopyRemovalIndicator,
            },
        }).AsTask();
        Assert(sink.Items.Count == 1, "Recovery indicator label must create one evidence item.");
        Assert(sink.Items[0].RecoveryIndicators.Contains(
                DataVanger.Engine.ProtectedFiles.RecoveryProtectionIndicators.ShadowCopyRemovalIndicator),
            "Recovery indicator label must be carried in evidence.");
        Assert(sink.Items[0].Severity ==
                DataVanger.Shared.ProtectedFiles.ProtectedFilesActivitySeverity.Suspicious,
            "A single recovery indicator label must be Suspicious only (evidence, not confirmation).");
        Assert(!sink.Items[0].IsConfirmedMalware,
            "Recovery indicator label alone must NOT be ConfirmedMalware.");
    }

    // 30g. Fully correlated activity reaches the top label
    //      (ProtectedActivitySuspected) but is STILL evidence only.
    {
        var sink = new CollectingProtectedFilesEvidenceSink();
        using var m = new DataVanger.Engine.ProtectedFiles.ProtectedFilesActivityMonitor(
            DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityOptions.Passive(),
            pipeline: null, evidenceSink: sink, timeProvider: () => pfaNow);
        await m.StartAsync();
        for (int i = 0; i < 60; i++)
            await m.HandleAsync(PfaFile(DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.FileChanged,
                $@"C:\Users\bob\Documents\d{i % 30}\m{i}.docx", pid: 9)).AsTask();
        for (int i = 0; i < 40; i++)
            await m.HandleAsync(PfaFile(DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.FileRenamed,
                $@"C:\Users\bob\Documents\r{i}.locked", pid: 9, previousPath: $@"C:\Users\bob\Documents\r{i}.docx"))
                .AsTask();
        await m.HandleAsync(new DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent
        {
            Category = DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.TamperObserved,
            ProcessId = 9, ProcessName = "evil.exe", TimestampUtc = pfaNow,
            Metadata = new Dictionary<string, string>
            {
                [DataVanger.Engine.ProtectedFiles.RecoveryProtectionIndicators.MetaSingle] =
                    DataVanger.Engine.ProtectedFiles.RecoveryProtectionIndicators.ShadowCopyRemovalIndicator,
            },
        }).AsTask();
        var top = sink.Items.OrderByDescending(e => e.Severity).First();
        Assert(top.Severity ==
                DataVanger.Shared.ProtectedFiles.ProtectedFilesActivitySeverity.ProtectedActivitySuspected,
            "Fully correlated activity must reach the top ProtectedActivitySuspected label.");
        Assert(top.Confidence == DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityConfidence.High,
            "Top label must be high confidence.");
        Assert(!top.IsConfirmedMalware,
            "Even ProtectedActivitySuspected must NOT be ConfirmedMalware (anti-FP).");
        Assert(top.Reasons.Count >= 3, "Top evidence must carry explainable reasons.");
    }

    // 30h. Entropy delta is a weak, gated signal: entropy-only activity
    //      never reaches the top label and never confirms malware.
    {
        var opts = new DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityOptions
        {
            Mode = DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityMode.Passive,
            EnableEntropySampling = true,
        };
        var sink = new CollectingProtectedFilesEvidenceSink();
        using var m = new DataVanger.Engine.ProtectedFiles.ProtectedFilesActivityMonitor(
            opts, pipeline: null, evidenceSink: sink, timeProvider: () => pfaNow);
        await m.StartAsync();
        for (int i = 0; i < 5; i++)
            await m.HandleAsync(PfaFile(DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.FileChanged,
                $@"C:\Users\bob\Documents\e{i}.docx", entropyAfter: 7.9, entropyBefore: 3.0))
                .AsTask();
        Assert(sink.Items.All(e =>
                e.Severity < DataVanger.Shared.ProtectedFiles.ProtectedFilesActivitySeverity.ProtectedActivitySuspected),
            "Entropy-only activity must never reach the top label.");
        Assert(sink.Items.All(e => !e.IsConfirmedMalware),
            "Entropy increase alone must never be ConfirmedMalware.");

        // Pure entropy helper sanity (no file I/O).
        Assert(DataVanger.Engine.ProtectedFiles.EntropyDeltaAnalyzer
                .ComputeShannonEntropy(new byte[1024]) < 0.01,
            "All-zero buffer must have near-zero entropy.");
        var rnd = new byte[4096];
        new Random(7).NextBytes(rnd);
        Assert(DataVanger.Engine.ProtectedFiles.EntropyDeltaAnalyzer.ComputeShannonEntropy(rnd) > 7.5,
            "A random buffer must have high entropy.");
    }

    // 30i. Bounded state respects MaxTrackedProcesses and degrades gracefully.
    {
        var opts = new DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityOptions
        {
            Mode = DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityMode.Passive,
            MaxTrackedProcesses = 3,
        };
        var sink = new CollectingProtectedFilesEvidenceSink();
        using var m = new DataVanger.Engine.ProtectedFiles.ProtectedFilesActivityMonitor(
            opts, pipeline: null, evidenceSink: sink, timeProvider: () => pfaNow);
        await m.StartAsync();
        for (int i = 0; i < 20; i++)
            await m.HandleAsync(PfaFile(DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.FileChanged,
                @"C:\Users\bob\Documents\x.docx", pid: 1000 + i, proc: "p" + i))
                .AsTask();
        var h = m.GetHealthSnapshot();
        Assert(h.TrackedProcessCount <= 3, "Tracked processes must respect MaxTrackedProcesses.");
        Assert(h.EventsDropped > 0, "State-pressure eviction must increment the dropped counter.");
        Assert(h.State == DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityMonitorState.Degraded,
            "Reaching the state limit must degrade gracefully (not crash).");
        Assert(h.LastWarning != null && h.LastWarning.Contains("state limit"),
            "Degraded status must carry a state-limit warning.");
    }

    // 30j. TTL cleanup expires old activity state deterministically.
    {
        var tracker = new DataVanger.Engine.ProtectedFiles.ActivityTracker(
            new DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityOptions
            {
                ProcessStateTtl = TimeSpan.FromMinutes(10),
            }.WithSafeDefaults());
        tracker.GetOrCreate("pid:1", pfaNow, out _);
        Assert(tracker.Count == 1, "Activity state must be tracked.");
        tracker.Prune(pfaNow.AddMinutes(11));
        Assert(tracker.Count == 0, "TTL cleanup must expire stale activity state.");
        Assert(tracker.Expirations == 1, "TTL expirations must be counted.");
    }

    // 30k. Rate limiting drops overflow events and counts them.
    {
        var opts = new DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityOptions
        {
            Mode = DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityMode.Passive,
            MaxEventsPerMinute = 2,
        };
        var sink = new CollectingProtectedFilesEvidenceSink();
        using var m = new DataVanger.Engine.ProtectedFiles.ProtectedFilesActivityMonitor(
            opts, pipeline: null, evidenceSink: sink, timeProvider: () => pfaNow);
        await m.StartAsync();
        for (int i = 0; i < 5; i++)
            await m.HandleAsync(PfaFile(DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.FileChanged,
                @"C:\Users\bob\Documents\a.docx")).AsTask();
        var h = m.GetHealthSnapshot();
        Assert(h.EventsReceived == 5, "All received events must be counted.");
        Assert(h.EventsDropped >= 3, "Rate-limit overflow must be dropped and counted.");
    }

    // 30l. Pipeline subscription, start/stop idempotency, cancellation, and
    //      no surviving background work.
    {
        using var pfaPipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
        var sink = new CollectingProtectedFilesEvidenceSink();
        using var m = new DataVanger.Engine.ProtectedFiles.ProtectedFilesActivityMonitor(
            DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityOptions.Passive(),
            pipeline: pfaPipeline, evidenceSink: sink, timeProvider: () => pfaNow);
        await m.StartAsync();
        await m.StartAsync(); // idempotent
        for (int i = 0; i < 60; i++)
            await pfaPipeline.PublishAsync(PfaFile(DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.FileChanged,
                $@"C:\Users\bob\Documents\p{i}.docx")).AsTask();
        Assert(sink.Items.Count >= 1, "Pipeline-driven events must reach the monitor.");
        var afterStart = sink.Items.Count;

        await m.StopAsync();
        await m.StopAsync(); // idempotent
        await pfaPipeline.PublishAsync(PfaFile(DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.FileChanged,
            @"C:\Users\bob\Documents\z.docx")).AsTask();
        Assert(sink.Items.Count == afterStart,
            "After StopAsync the monitor must be unsubscribed and inert.");

        // Repeated start/stop is await safe.
        _ = m.StartAsync();  // CS4014: intentional fire-and-forget (original behaviour; result deliberately not observed here)
        await m.StopAsync();

        // Cancellation is respected and never throws.
        var pfaCancelledToken = new CancellationToken(canceled: true);
        await m.HandleAsync(PfaFile(DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.FileChanged,
            @"C:\Users\bob\Documents\c.docx"), pfaCancelledToken).AsTask();
    }

    // 30m. Helper correctness: recovery label extraction (labels only) and
    //      conservative extension-transition analysis (no false positives on
    //      ordinary refactors / temp files).
    {
        var labels = DataVanger.Engine.ProtectedFiles.RecoveryProtectionIndicators.Extract(
            new Dictionary<string, string>
            {
                ["protectedfiles.recovery.shadow_copy_removal"] = "true",
                ["protectedfiles.recovery_indicator"] =
                    DataVanger.Engine.ProtectedFiles.RecoveryProtectionIndicators.BackupCatalogRemovalIndicator,
            });
        Assert(labels.Contains(
                DataVanger.Engine.ProtectedFiles.RecoveryProtectionIndicators.ShadowCopyRemovalIndicator),
            "Flag-form recovery indicator label must be extracted.");
        Assert(labels.Contains(
                DataVanger.Engine.ProtectedFiles.RecoveryProtectionIndicators.BackupCatalogRemovalIndicator),
            "Single-form recovery indicator label must be extracted.");

        Assert(DataVanger.Engine.ProtectedFiles.ExtensionTransitionAnalyzer
                .IsSuspiciousTransition(@"a\x.docx", @"a\x.locked"),
            ".docx -> .locked must be a suspicious transition.");
        Assert(!DataVanger.Engine.ProtectedFiles.ExtensionTransitionAnalyzer
                .IsSuspiciousTransition(@"a\x.docx", @"a\x.docx.tmp"),
            "A transient .tmp suffix must NOT be suspicious.");
        Assert(!DataVanger.Engine.ProtectedFiles.ExtensionTransitionAnalyzer
                .IsSuspiciousTransition(@"a\x.cs", @"a\y.cs"),
            "An ordinary source refactor must NOT be suspicious.");
    }

    // 30n. Anti-FP structural guarantee: activity evidence exposes no
    //      confirmation/remediation surface and IsConfirmedMalware is a
    //      constant; the severity enum has no Confirmed member.
    {
        var t = typeof(DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityEvidence);
        var remediation = t.GetProperties()
            .Where(p =>
                p.Name.Contains("Quarantine", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Kill", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Suspend", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Block", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Inject", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        Assert(remediation.Length == 0,
            "ProtectedFilesActivityEvidence must NOT expose any remediation surface.");
        var evidence = new DataVanger.Shared.ProtectedFiles.ProtectedFilesActivityEvidence();
        Assert(!evidence.IsConfirmedMalware,
            "ProtectedFilesActivityEvidence.IsConfirmedMalware must be a constant false.");
        var maxSeverity = Enum.GetValues(typeof(DataVanger.Shared.ProtectedFiles.ProtectedFilesActivitySeverity))
            .Cast<int>().Max();
        Assert(maxSeverity == (int)DataVanger.Shared.ProtectedFiles.ProtectedFilesActivitySeverity.ProtectedActivitySuspected,
            "ProtectedFilesActivitySeverity must top out at ProtectedActivitySuspected (no Confirmed member).");
    }
}
}
