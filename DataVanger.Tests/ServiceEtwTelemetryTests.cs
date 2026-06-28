using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Behavioral;
using DataVanger.Core;
using DataVanger.Infrastructure.Etw;
using DataVanger.Service.Runtime;
using DataVanger.Service.RuntimeEvents;
using DataVanger.Shared.Etw;
using DataVanger.Shared.Service;
using Xunit;

// Phase 17 — service-side activation of the existing real ETW runtime provider.
//
// These tests prove the SERVICE runtime can host the already-gated, bounded
// WindowsEtwRuntimeProvider behind an explicit opt-in config gate, while:
//   - staying fully passive by default (gate OFF),
//   - degrading to the Null provider without crashing when unavailable,
//   - never claiming active protection,
//   - keeping the behavioral clamp intact (runtime/behavioral evidence can
//     never confirm malware on its own).
//
// A test-only platform probe forces the ETW platform gate to "unsupported" so
// NO real ETW session is ever opened during automated tests on any host.
// Real Windows/admin capture is covered by the manual validation plan.
// Filters: ~Service, ~Etw.
public class ServiceEtwTelemetryTests
{
    private static DataVangerServiceConfiguration EtwOn()
        => new() { EnableEtwRuntimeTelemetry = true };

    // ── Default OFF: runtime stays passive, placeholder unchanged ────────────

    [Fact]
    public async Task EtwDisabledByDefault_RuntimeStaysPassive()
    {
        using var rt = new DataVangerServiceRuntime(
            DataVangerServiceConfiguration.SafeDefaults(), DataVangerRuntimeMode.Service);
        await rt.StartAsync(CancellationToken.None);

        var snap = rt.GetStatusSnapshot();
        Assert.Equal(DataVangerServiceState.Running, rt.State);
        Assert.False(snap.HasActiveProtection);
        var tele = snap.Modules.Single(m => m.Name == "RuntimeTelemetryPlaceholder");
        Assert.Equal(RuntimeModuleAvailability.NotImplemented, tele.Availability);

        await rt.StopAsync(CancellationToken.None);
    }

    // ── Enabled but unavailable (forced) → safe fallback, still Running ──────

    [Fact]
    public async Task EtwEnabled_Unavailable_FallsBackSafely_NoCrash_NoActiveProtection()
    {
        // Force "platform unsupported" so the factory returns the Null provider
        // deterministically — no real ETW session is ever opened.
        using var rt = new DataVangerServiceRuntime(
            EtwOn(), DataVangerRuntimeMode.Service, configWarnings: null, etwPlatformProbe: () => false);

        await rt.StartAsync(CancellationToken.None);

        Assert.Equal(DataVangerServiceState.Running, rt.State);
        var snap = rt.GetStatusSnapshot();
        Assert.False(snap.HasActiveProtection); // telemetry never claims active protection

        var tele = snap.Modules.Single(m => m.Name == "RuntimeTelemetry");
        Assert.NotEqual(RuntimeModuleAvailability.Available, tele.Availability);
        Assert.False(tele.IsActiveProtection);
        Assert.Contains(snap.Warnings, w => w.Contains("ETW runtime telemetry", StringComparison.OrdinalIgnoreCase));

        await rt.StopAsync(CancellationToken.None);
        Assert.Equal(DataVangerServiceState.Stopped, rt.State);
    }

    [Fact]
    public async Task EtwEnabled_StartStopDispose_AreIdempotentAndSafe()
    {
        var rt = new DataVangerServiceRuntime(
            EtwOn(), DataVangerRuntimeMode.Service, configWarnings: null, etwPlatformProbe: () => false);

        await rt.StartAsync(CancellationToken.None);
        await rt.StartAsync(CancellationToken.None); // idempotent
        await rt.StopAsync(CancellationToken.None);
        await rt.StopAsync(CancellationToken.None);  // double-stop safe
        rt.Dispose();
        rt.Dispose();                                 // double-dispose safe

        Assert.Equal(DataVangerServiceState.Stopped, rt.State);
    }

    [Fact]
    public async Task EtwEnabled_InDevelopmentMode_DegradesToNull_NoRealSession()
    {
        // Development mode keeps the provider's DevelopmentMode=true, so the
        // factory returns Null even with AllowRealProvider — never a real session.
        using var rt = new DataVangerServiceRuntime(EtwOn(), DataVangerRuntimeMode.Development);
        await rt.StartAsync(CancellationToken.None);

        Assert.Equal(DataVangerServiceState.Running, rt.State);
        Assert.False(rt.GetStatusSnapshot().HasActiveProtection);

        await rt.StopAsync(CancellationToken.None);
    }

    // ── Behavioral runtime correlation binds to the ETW pipeline (passive) ───

    [Fact]
    public async Task EtwEnabled_Service_BindsBehavioralRuntime_Passive_NeverActiveProtection()
    {
        // Even with the real ETW session forced unavailable, the behavioral
        // consumer is bound to the SAME runtime-event pipeline. In Service mode it
        // runs Passive and must NEVER be reported as active protection.
        using var rt = new DataVangerServiceRuntime(
            EtwOn(), DataVangerRuntimeMode.Service, configWarnings: null, etwPlatformProbe: () => false);

        await rt.StartAsync(CancellationToken.None);

        var snap = rt.GetStatusSnapshot();
        Assert.False(snap.HasActiveProtection);
        var beh = snap.Modules.Single(m => m.Name == "BehavioralRuntime");
        Assert.Equal(RuntimeModuleAvailability.Passive, beh.Availability);
        Assert.False(beh.IsActiveProtection);

        await rt.StopAsync(CancellationToken.None);
        Assert.Equal(DataVangerServiceState.Stopped, rt.State);
    }

    [Fact]
    public async Task EtwDisabled_BehavioralRuntime_StaysPassiveForAmsiSubmissions()
    {
        using var rt = new DataVangerServiceRuntime(
            DataVangerServiceConfiguration.SafeDefaults(), DataVangerRuntimeMode.Service);
        await rt.StartAsync(CancellationToken.None);

        var snap = rt.GetStatusSnapshot();
        var behavioral = Assert.Single(snap.Modules, m => m.Name == "BehavioralRuntime");
        Assert.Equal(RuntimeModuleAvailability.Passive, behavioral.Availability);
        Assert.Contains(snap.Modules, m => m.Name == "AmsiRuntime"
            && m.Availability == RuntimeModuleAvailability.Passive);
        Assert.False(snap.HasActiveProtection);

        await rt.StopAsync(CancellationToken.None);
    }

    // ── Provider selection: never returns the real Windows provider off-Windows ─

    [Fact]
    public void Host_CreateProvider_NonWindows_ReturnsNull_NeverReal()
    {
        var pipeline = RuntimeEventPipelineFactory.CreateDevelopmentPipeline();
        try
        {
            var cfg = new EtwProviderConfiguration
            {
                Enabled = true,
                AllowRealProvider = true,
                DevelopmentMode = false,
                CaptureProcessStart = true,
            };
            var provider = EtwRuntimeProviderHost.CreateProvider(pipeline, cfg, platformProbeOverride: () => false);
            Assert.NotEqual("windows-etw", provider.Name); // Null fallback, not the real session
        }
        finally
        {
            pipeline.Dispose();
        }
    }

    // ── Bounds are clamped (capture cannot be unbounded) ─────────────────────

    [Fact]
    public void EtwProviderConfiguration_Bounds_AreClampedToSafeRange()
    {
        var floored = new EtwProviderConfiguration { MaxEventsPerSecond = -5, MaxQueueSize = 0 }.WithSafeDefaults();
        Assert.Equal(100, floored.MaxEventsPerSecond);
        Assert.Equal(1024, floored.MaxQueueSize);

        var capped = new EtwProviderConfiguration { MaxEventsPerSecond = 10_000_000, MaxQueueSize = 10_000_000 }.WithSafeDefaults();
        Assert.True(capped.MaxEventsPerSecond <= 100_000);
        Assert.True(capped.MaxQueueSize <= 1_000_000);
    }

    [Fact]
    public void ServiceEtwRichCapture_DefaultsOff_AndRequiresExplicitConfiguration()
    {
        var defaults = DataVangerServiceConfiguration.SafeDefaults();
        Assert.False(defaults.CaptureEtwCommandLine);
        Assert.False(defaults.CaptureEtwPowerShellSignals);

        var optedIn = new DataVangerServiceConfiguration
        {
            EnableEtwRuntimeTelemetry = true,
            CaptureEtwCommandLine = true,
            CaptureEtwPowerShellSignals = true,
        };
        Assert.True(optedIn.CaptureEtwCommandLine);
        Assert.True(optedIn.CaptureEtwPowerShellSignals);
    }

    // ── Clamp proof: runtime/behavioral evidence can NEVER confirm malware ───

    [Fact]
    public void BehavioralClamp_RuntimeEvidence_NeverConfirms_AndClampsToHigh()
    {
        var engine = new BehavioralCorrelationEngine();
        var ancestry = new ProcessAncestry();
        var ev = new BehavioralEvent(
            kind: BehavioralEventKind.ProcessStart,
            pid: 4242,
            parentPid: 0,
            processName: "suspect.exe",
            imagePath: @"C:\tmp\suspect.exe",
            commandLine: "",
            targetPath: "",
            extraTag: "",
            severity: BehavioralSeverity.Info,
            description: "synthetic runtime telemetry",
            timestampUtc: DateTime.UtcNow);

        // Hostile input: evidence falsely marked Confirmed / CanConfirmMalware
        // with a huge score. The chain must downgrade and clamp it.
        var evidence = new List<Evidence>
        {
            new() { Category = "Runtime", Description = "etw/amsi runtime signal",
                    ScoreDelta = 100_000, Strength = EvidenceStrength.Confirmed, CanConfirmMalware = true },
        };

        var chain = engine.Record(ev, evidence, ancestry);

        Assert.True(chain.Score > 0, "Chain must record the runtime evidence.");
        Assert.True(chain.Score <= RiskThresholds.High, "Behavioral chain score must clamp to High.");
        Assert.All(chain.Evidence, e => Assert.False(e.CanConfirmMalware));
        Assert.All(chain.Evidence, e => Assert.NotEqual(EvidenceStrength.Confirmed, e.Strength));
    }
}
