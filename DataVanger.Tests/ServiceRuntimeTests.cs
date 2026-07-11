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

// Phase 09 decomposition — Windows Service Host runtime lifecycle (Phase 2 / Step 02). Filter: ~Service.
// Faithful move of the legacy mega-[Fact] section into an independently
// runnable, filterable [Fact]. Body is verbatim; the private Assert shim
// delegates to LegacyAssert.True so condition AND message are preserved.
public class ServiceRuntimeTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public async Task WindowsServiceHost_AllLegacyChecks()
// 25. Windows Service Host (Phase 2 / Step 02) — deterministic, development-safe
//     lifecycle tests for DataVangerServiceRuntime. None of these tests may
//     require admin, install a Windows Service, or leave background work behind.
{
    static DataVanger.Service.Runtime.DataVangerServiceRuntime NewDevelopmentRuntime()
        => new DataVanger.Service.Runtime.DataVangerServiceRuntime(
            DataVanger.Shared.Service.DataVangerServiceConfiguration.SafeDefaults(),
            DataVanger.Shared.Service.DataVangerRuntimeMode.Development);

    // 25a. Fresh runtime starts in NotStarted, Development mode, no started-at,
    //      and reports HasActiveProtection=false because every module is passive.
    {
        using var rt = NewDevelopmentRuntime();
        Assert(rt.State == DataVanger.Shared.Service.DataVangerServiceState.NotStarted,
            "New runtime must report NotStarted.");
        Assert(rt.Mode == DataVanger.Shared.Service.DataVangerRuntimeMode.Development,
            "New runtime must default to Development mode.");
        var snap0 = rt.GetStatusSnapshot();
        Assert(snap0.StartedAtUtc is null,
            "StartedAtUtc must be null before StartAsync.");
        Assert(!snap0.HasActiveProtection,
            "Service host must NOT claim active protection at construction.");
        Assert(snap0.Modules.Count >= 6,
            "Status snapshot must surface the registered placeholder modules.");
        foreach (var m in snap0.Modules)
        {
            Assert(m.Availability != DataVanger.Shared.Service.RuntimeModuleAvailability.Available
                || m.Name == "Configuration",
                $"Only the Configuration module may be Available in this phase; module '{m.Name}' must remain passive.");
        }
    }

    // 25b. Start then Stop transitions Running -> Stopped cleanly.
    {
        using var rt = NewDevelopmentRuntime();
        await rt.StartAsync(CancellationToken.None);
        Assert(rt.State == DataVanger.Shared.Service.DataVangerServiceState.Running,
            "After StartAsync the runtime must be Running.");
        var startedSnap = rt.GetStatusSnapshot();
        Assert(startedSnap.StartedAtUtc is not null,
            "StartedAtUtc must be populated after StartAsync.");

        await rt.StopAsync(CancellationToken.None);
        Assert(rt.State == DataVanger.Shared.Service.DataVangerServiceState.Stopped,
            "After StopAsync the runtime must be Stopped.");
    }

    // 25c. StopAsync before StartAsync is safe and leaves the runtime in
    //      a terminal Stopped state without exceptions.
    {
        using var rt = NewDevelopmentRuntime();
        await rt.StopAsync(CancellationToken.None);
        Assert(rt.State == DataVanger.Shared.Service.DataVangerServiceState.Stopped,
            "StopAsync before StartAsync must transition to Stopped safely.");
    }

    // 25d. StartAsync is idempotent — double start must not duplicate state.
    {
        using var rt = NewDevelopmentRuntime();
        await rt.StartAsync(CancellationToken.None);
        var firstStartedAt = rt.GetStatusSnapshot().StartedAtUtc;
        await rt.StartAsync(CancellationToken.None);
        var secondStartedAt = rt.GetStatusSnapshot().StartedAtUtc;
        Assert(rt.State == DataVanger.Shared.Service.DataVangerServiceState.Running,
            "Double StartAsync must leave the runtime Running.");
        Assert(firstStartedAt == secondStartedAt,
            "Idempotent StartAsync must NOT reset StartedAtUtc.");
        await rt.StopAsync(CancellationToken.None);
    }

    // 25e. StopAsync is idempotent — double stop must not throw.
    {
        using var rt = NewDevelopmentRuntime();
        await rt.StartAsync(CancellationToken.None);
        await rt.StopAsync(CancellationToken.None);
        await rt.StopAsync(CancellationToken.None);
        Assert(rt.State == DataVanger.Shared.Service.DataVangerServiceState.Stopped,
            "Double StopAsync must remain Stopped.");
    }

    // 25f. Cancellation before StartAsync is honored without partial state.
    {
        using var rt = NewDevelopmentRuntime();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var task = rt.StartAsync(cts.Token);
        Assert(task.IsCanceled || task.IsFaulted || task.IsCompleted,
            "StartAsync must complete (canceled or done) when the token is pre-cancelled.");
        // Either Canceled (preferred) or completed-to-Stopped is acceptable —
        // both leave the runtime safe to dispose.
        Assert(rt.State == DataVanger.Shared.Service.DataVangerServiceState.Stopped
            || rt.State == DataVanger.Shared.Service.DataVangerServiceState.NotStarted,
            "Cancelled StartAsync must NOT leave the runtime mid-state.");
    }

    // 25g. Development mode is safe by default and snapshot says so.
    {
        using var rt = NewDevelopmentRuntime();
        await rt.StartAsync(CancellationToken.None);
        var snap = rt.GetStatusSnapshot();
        Assert(snap.IsDevelopmentMode,
            "Default runtime must self-report Development mode.");
        Assert(!snap.IsServiceMode,
            "Default runtime must NOT self-report Service mode.");
        Assert(!snap.HasActiveProtection,
            "Development runtime must never report active protection in this phase.");
        await rt.StopAsync(CancellationToken.None);
    }

    // 25h. ForceDevelopmentMode in configuration wins even when Service mode
    //      is requested — accidental --service execution stays safe.
    {
        var cfg = new DataVanger.Shared.Service.DataVangerServiceConfiguration
        {
            ForceDevelopmentMode = true,
        };
        using var rt = new DataVanger.Service.Runtime.DataVangerServiceRuntime(
            cfg, DataVanger.Shared.Service.DataVangerRuntimeMode.Service);
        Assert(rt.Mode == DataVanger.Shared.Service.DataVangerRuntimeMode.Development,
            "ForceDevelopmentMode must override the requested Service mode.");
        await rt.StartAsync(CancellationToken.None);
        var snap = rt.GetStatusSnapshot();
        Assert(snap.IsDevelopmentMode,
            "Snapshot must reflect Development mode after override.");
        await rt.StopAsync(CancellationToken.None);
    }

    // 25i. ServiceEnabled=false starts the runtime in Degraded passive state
    //      with a warning and still without any active protection claim.
    {
        var cfg = new DataVanger.Shared.Service.DataVangerServiceConfiguration
        {
            ServiceEnabled = false,
        };
        using var rt = new DataVanger.Service.Runtime.DataVangerServiceRuntime(
            cfg, DataVanger.Shared.Service.DataVangerRuntimeMode.Development);
        await rt.StartAsync(CancellationToken.None);
        Assert(rt.State == DataVanger.Shared.Service.DataVangerServiceState.Degraded,
            "ServiceEnabled=false must produce Degraded state, not Failed.");
        var snap = rt.GetStatusSnapshot();
        Assert(snap.Warnings.Count >= 1,
            "Degraded startup must surface at least one warning.");
        Assert(!snap.HasActiveProtection,
            "Degraded runtime must NEVER claim active protection.");
        await rt.StopAsync(CancellationToken.None);
    }

    // 25j. Configuration loader: missing file => safe defaults, no warnings.
    {
        var load = DataVanger.Service.Configuration.ServiceConfigurationLoader
            .LoadFromFile(Path.Combine(Path.GetTempPath(),
                $"datavanger-service-missing-{Guid.NewGuid():N}.json"));
        Assert(!load.LoadedFromSource,
            "Missing config file must NOT report LoadedFromSource=true.");
        Assert(load.Warnings.Count == 0,
            "Missing config file must NOT produce warnings (silent fallback).");
        Assert(load.Configuration.ServiceEnabled,
            "Safe defaults must keep ServiceEnabled=true.");
    }

    // 25k. Configuration loader: malformed JSON => safe defaults + warning,
    //      never throws. The duplicate-"malformed"-local regression guard
    //      requires us to keep this single, locally-scoped usage.
    {
        var loadBad = DataVanger.Service.Configuration.ServiceConfigurationLoader
            .ParseJsonOrDefault("{ this is not json ");
        Assert(!loadBad.LoadedFromSource,
            "Malformed config must NOT report LoadedFromSource=true.");
        Assert(loadBad.Warnings.Count >= 1,
            "Malformed config must surface a warning.");
        Assert(loadBad.Configuration.ServiceEnabled,
            "Malformed config must still produce safe defaults.");
    }

    // 25l. Lifecycle is free of background work — many start/stop cycles
    //      must complete in well under a second.
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        for (int i = 0; i < 50; i++)
        {
            using var rt = NewDevelopmentRuntime();
            await rt.StartAsync(CancellationToken.None);
            await rt.StopAsync(CancellationToken.None);
        }
        sw.Stop();
        Assert(sw.ElapsedMilliseconds < 2000,
            $"DataVangerServiceRuntime lifecycle must be free of background work (took {sw.ElapsedMilliseconds}ms).");
    }

    // 25m. Disposed runtime never resurrects.
    {
        var rt = NewDevelopmentRuntime();
        await rt.StartAsync(CancellationToken.None);
        rt.Dispose();
        Assert(rt.State == DataVanger.Shared.Service.DataVangerServiceState.Stopped,
            "Disposed runtime must report Stopped.");
        await rt.StartAsync(CancellationToken.None);
        Assert(rt.State == DataVanger.Shared.Service.DataVangerServiceState.Stopped,
            "Disposed runtime must remain Stopped after a subsequent StartAsync.");
    }

    // 25n. Anti-FP guard: a Degraded state + multiple warnings still must
    //      not flip HasActiveProtection true, and every placeholder module
    //      must individually refuse the "active protection" label.
    {
        var cfg = new DataVanger.Shared.Service.DataVangerServiceConfiguration
        {
            ServiceEnabled = false,
        };
        using var rt = new DataVanger.Service.Runtime.DataVangerServiceRuntime(
            cfg,
            DataVanger.Shared.Service.DataVangerRuntimeMode.Development,
            new[] { "synthetic config warning A", "synthetic config warning B" });
        await rt.StartAsync(CancellationToken.None);
        var snap = rt.GetStatusSnapshot();
        Assert(!snap.HasActiveProtection,
            "Service status with warnings/degraded must NEVER claim active protection.");
        foreach (var m in snap.Modules)
        {
            if (m.Name == "RealtimeProtectionPlaceholder"
                || m.Name == "RuntimeTelemetryPlaceholder")
            {
                Assert(m.Availability == DataVanger.Shared.Service.RuntimeModuleAvailability.NotImplemented,
                    $"Placeholder module '{m.Name}' must remain NotImplemented in this phase.");
                Assert(!m.IsActiveProtection,
                    $"Placeholder module '{m.Name}' must NEVER report itself as active protection.");
            }
        }
        await rt.StopAsync(CancellationToken.None);
    }
}

}
