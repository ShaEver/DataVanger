using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Service.Hosting;
using DataVanger.Service.Runtime;
using DataVanger.Shared.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

// Phase 15 — Windows service lifecycle.
//
// These tests cover the testable surface WITHOUT installing a real service or
// requiring admin rights:
//   - the hosted worker maps host start/stop onto the runtime state machine;
//   - the sc.exe install/uninstall/recovery PLANS are explicit and safe;
//   - service mode never claims active protection (anti-FP preserved).
//
// The real install/start/stop/recovery drill is Windows + admin only and is
// documented as manual validation in the phase report. Filter: ~Service.
public class ServiceLifecycleTests
{
    private static DataVangerServiceWorker NewWorker(DataVangerServiceRuntime runtime)
        => new(runtime, NullLogger<DataVangerServiceWorker>.Instance);

    private static DataVangerServiceRuntime NewServiceRuntime()
        => new(DataVangerServiceConfiguration.SafeDefaults(), DataVangerRuntimeMode.Service);

    // ── Worker ↔ runtime lifecycle mapping ──────────────────────────────────

    [Fact]
    public async Task Worker_Start_StartsRuntime()
    {
        using var runtime = NewServiceRuntime();
        var worker = NewWorker(runtime);

        await worker.StartAsync(CancellationToken.None);

        Assert.Equal(DataVangerServiceState.Running, runtime.State);
    }

    [Fact]
    public async Task Worker_Stop_StopsRuntime()
    {
        using var runtime = NewServiceRuntime();
        var worker = NewWorker(runtime);

        await worker.StartAsync(CancellationToken.None);
        await worker.StopAsync(CancellationToken.None);

        Assert.Equal(DataVangerServiceState.Stopped, runtime.State);
    }

    [Fact]
    public async Task Worker_RepeatedStop_IsSafe()
    {
        using var runtime = NewServiceRuntime();
        var worker = NewWorker(runtime);

        await worker.StartAsync(CancellationToken.None);
        await worker.StopAsync(CancellationToken.None);
        await worker.StopAsync(CancellationToken.None);

        Assert.Equal(DataVangerServiceState.Stopped, runtime.State);
    }

    [Fact]
    public async Task ServiceMode_NeverClaimsActiveProtection()
    {
        using var runtime = NewServiceRuntime();
        var worker = NewWorker(runtime);

        await worker.StartAsync(CancellationToken.None);
        Assert.False(runtime.GetStatusSnapshot().HasActiveProtection);
        await worker.StopAsync(CancellationToken.None);
    }

    // ── Install / uninstall / recovery plans (pure, no execution) ────────────

    [Fact]
    public void InstallPlan_IsExplicit_DemandStart_AndConfiguresRecovery()
    {
        var plan = WindowsServiceInstaller.BuildInstallPlan(
            "\"C:\\dv\\DataVanger.Service.exe\" --service");

        // Always sc.exe with a structured arg list — never a shell string.
        Assert.All(plan, c => Assert.Equal("sc.exe", c.FileName));

        var create = plan.Single(c => c.Arguments[0] == "create");
        Assert.Contains(WindowsServiceInstaller.ServiceName, create.Arguments);
        Assert.Contains("binPath=", create.Arguments);
        Assert.Contains("start=", create.Arguments);
        // start=demand → never auto-started by installation.
        Assert.Contains("demand", create.Arguments);
        Assert.DoesNotContain("auto", create.Arguments);

        // Restart-on-failure recovery is part of the install plan.
        Assert.Contains(plan, c => c.Arguments[0] == "failure");
    }

    [Fact]
    public void UninstallPlan_StopsThenDeletes()
    {
        var plan = WindowsServiceInstaller.BuildUninstallPlan();

        Assert.Equal(2, plan.Count);
        Assert.Equal("stop", plan[0].Arguments[0]);
        Assert.Equal("delete", plan[1].Arguments[0]);
        Assert.All(plan, c => Assert.Contains(WindowsServiceInstaller.ServiceName, c.Arguments));
    }

    [Fact]
    public void ResolveBinPath_IncludesServiceRunFlag()
    {
        var binPath = WindowsServiceInstaller.ResolveServiceBinPath();
        Assert.Contains("--service", binPath);
    }

    [Fact]
    public void BuildBinPath_PrefersRealAppHost_NotTheDotnetMuxer()
    {
        // When a real apphost exists, the service must run via that executable so
        // the SCM controls the actual process (the 1061 stop-path fix).
        var binPath = WindowsServiceInstaller.BuildBinPath(
            appHostPath: @"C:\dv\DataVanger.Service.exe",
            hostPath: @"C:\Program Files\dotnet\dotnet.exe",
            entryDll: @"C:\dv\DataVanger.Service.dll");

        Assert.Equal("\"C:\\dv\\DataVanger.Service.exe\" --service", binPath);
        Assert.DoesNotContain("dotnet", binPath);
        Assert.Contains("--service", binPath);
    }

    [Fact]
    public void BuildBinPath_FallsBackToMuxer_WhenNoAppHost()
    {
        var binPath = WindowsServiceInstaller.BuildBinPath(
            appHostPath: null,
            hostPath: @"C:\Program Files\dotnet\dotnet.exe",
            entryDll: @"C:\dv\DataVanger.Service.dll");

        Assert.Equal(
            "\"C:\\Program Files\\dotnet\\dotnet.exe\" \"C:\\dv\\DataVanger.Service.dll\" --service",
            binPath);
        Assert.Contains("--service", binPath);
    }

    [Fact]
    public void BuildBinPath_UsesLaunchingHost_WhenNotMuxerAndNoAppHost()
    {
        var binPath = WindowsServiceInstaller.BuildBinPath(
            appHostPath: null,
            hostPath: @"C:\dv\DataVanger.Service.exe",
            entryDll: @"C:\dv\DataVanger.Service.dll");

        Assert.Equal("\"C:\\dv\\DataVanger.Service.exe\" --service", binPath);
    }

    [Fact]
    public void BuildBinPath_WithConfig_AppendsConfigArg_SoInstalledServiceLoadsIt()
    {
        var binPath = WindowsServiceInstaller.BuildBinPath(
            appHostPath: @"C:\dv\DataVanger.Service.exe",
            hostPath: @"C:\Program Files\dotnet\dotnet.exe",
            entryDll: @"C:\dv\DataVanger.Service.dll",
            configPath: @"C:\ProgramData\DataVanger\service.json");

        Assert.Equal(
            "\"C:\\dv\\DataVanger.Service.exe\" --service --config \"C:\\ProgramData\\DataVanger\\service.json\"",
            binPath);
        Assert.Contains("--service", binPath);
        Assert.Contains("--config", binPath);
    }

    [Fact]
    public void BuildBinPath_WithoutConfig_OmitsConfigArg()
    {
        var binPath = WindowsServiceInstaller.BuildBinPath(
            appHostPath: @"C:\dv\DataVanger.Service.exe",
            hostPath: null,
            entryDll: null);

        Assert.DoesNotContain("--config", binPath);
    }

    // ── Non-Windows graceful degradation (no crash, clear unsupported) ───────

    [Fact]
    public void Install_OnNonWindows_ReportsUnsupported_NoCrash()
    {
        if (OperatingSystem.IsWindows()) return;

        var output = new StringWriter();
        var error = new StringWriter();
        int code = WindowsServiceInstaller.Install(output, error);

        Assert.Equal(WindowsServiceInstaller.ExitSecureInstallerUnavailable, code);
        Assert.Contains("unavailable until a secure installer", error.ToString());
    }

    [Fact]
    public void Uninstall_OnNonWindows_ReportsUnsupported_NoCrash()
    {
        if (OperatingSystem.IsWindows()) return;

        var output = new StringWriter();
        var error = new StringWriter();
        int code = WindowsServiceInstaller.Uninstall(output, error);

        Assert.Equal(WindowsServiceInstaller.ExitUnsupportedPlatform, code);
        Assert.Contains("only on Windows", error.ToString());
    }
}
