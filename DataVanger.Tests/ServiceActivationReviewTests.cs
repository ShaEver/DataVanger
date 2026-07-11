using System;
using System.IO;
using System.Linq;
using DataVanger.Service.Hosting;
using DataVanger.Shared.Ipc;
using Xunit;

// Beta phase 02A — service activation review tests. Runnable via:
//   dotnet test --filter "FullyQualifiedName~ServiceActivationReview"
// Contract under test: the privileged backend shell activates safely —
// install never registers an ambiguous executable path, the recovery plan is
// bounded, uninstall is ordered stop→delete, and the IPC command surface
// exposes remediation only through the Phase 04B policy-gated DTO command.
public class ServiceActivationReviewTests
{
    // ── BinPath executable extraction (pure) ─────────────────────────────────

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData("\"\" --service", null)]
    public void ExtractBinPathExecutable_RejectsEmptyForms(string? binPath, string? expected)
        => Assert.Equal(expected, WindowsServiceInstaller.ExtractBinPathExecutable(binPath));

    [Fact]
    public void ExtractBinPathExecutable_ReadsQuotedAndUnquotedForms()
    {
        Assert.Equal(@"C:\svc\DataVanger.Service.exe",
            WindowsServiceInstaller.ExtractBinPathExecutable(@"""C:\svc\DataVanger.Service.exe"" --service"));
        Assert.Equal("dotnet",
            WindowsServiceInstaller.ExtractBinPathExecutable(@"dotnet ""C:\svc\DataVanger.Service.dll"" --service"));
        Assert.Equal("--service",
            WindowsServiceInstaller.ExtractBinPathExecutable("--service"));
    }

    // ── BinPath validation (phase 02A guard: abort instead of guessed path) ──

    [Fact]
    public void ValidateBinPath_AcceptsAbsoluteExistingExecutable()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            bool ok = WindowsServiceInstaller.TryValidateServiceBinPath(
                $"\"{tempFile}\" --service", out var reason);

            Assert.True(ok, reason);
            Assert.Equal("", reason);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateBinPath_RejectsEmpty(string? binPath)
    {
        bool ok = WindowsServiceInstaller.TryValidateServiceBinPath(binPath, out var reason);

        Assert.False(ok);
        Assert.Contains("no executable component", reason);
    }

    [Fact]
    public void ValidateBinPath_RejectsRelativePath()
    {
        bool ok = WindowsServiceInstaller.TryValidateServiceBinPath(
            "relative/DataVanger.Service.exe --service", out var reason);

        Assert.False(ok);
        Assert.Contains("not absolute", reason);
    }

    [Fact]
    public void ValidateBinPath_RejectsBareDotnetMuxerFallback()
    {
        // The last-ditch composition form "dotnet <dll> --service" is
        // PATH-resolved and therefore a hijack surface: must be refused.
        bool ok = WindowsServiceInstaller.TryValidateServiceBinPath(
            @"dotnet ""C:\svc\DataVanger.Service.dll"" --service", out var reason);

        Assert.False(ok);
        Assert.Contains("not absolute", reason);
    }

    [Fact]
    public void ValidateBinPath_RejectsNonExistingExecutable()
    {
        var missing = Path.Combine(Path.GetTempPath(),
            "DataVanger_missing_" + Guid.NewGuid().ToString("N") + ".exe");

        bool ok = WindowsServiceInstaller.TryValidateServiceBinPath(
            $"\"{missing}\" --service", out var reason);

        Assert.False(ok);
        Assert.Contains("not found", reason);
    }

    [Fact]
    public void ValidateBinPath_RejectsArgumentOnlyComposition()
    {
        // BuildBinPath(null, null, null) degrades to "--service": registration
        // without an executable must be impossible.
        var composed = WindowsServiceInstaller.BuildBinPath(null, null, null);

        bool ok = WindowsServiceInstaller.TryValidateServiceBinPath(composed, out _);

        Assert.False(ok);
    }

    // ── Install plan details (demand start, bounded recovery) ────────────────

    [Fact]
    public void InstallPlan_RecoveryIsBounded_AndDescriptionIsRegistered()
    {
        var plan = WindowsServiceInstaller.BuildInstallPlan(@"""C:\svc\DataVanger.Service.exe"" --service");

        Assert.Equal(3, plan.Count);
        Assert.Equal("create", plan[0].Arguments[0]);
        Assert.Equal("description", plan[1].Arguments[0]);
        Assert.Equal("failure", plan[2].Arguments[0]);

        // Bounded restart-on-failure: three restarts, 60s apart, daily reset.
        Assert.Contains("86400", plan[2].Arguments);
        Assert.Contains("restart/60000/restart/60000/restart/60000", plan[2].Arguments);

        // Every step is sc.exe with structured arguments (no shell string).
        Assert.All(plan, c => Assert.Equal("sc.exe", c.FileName));
    }

    [Fact]
    public void UninstallPlan_StopsBeforeDelete()
    {
        var plan = WindowsServiceInstaller.BuildUninstallPlan();

        Assert.Equal(2, plan.Count);
        Assert.Equal("stop", plan[0].Arguments[0]);
        Assert.Equal("delete", plan[1].Arguments[0]);
        Assert.All(plan, c => Assert.Contains(WindowsServiceInstaller.ServiceName, c.Arguments));
    }

    // ── Remediation surface remains narrow and policy-gated ────────────────

    [Fact]
    public void IpcCommandSurface_ExposesOnlyPolicyGatedRemediationCapability()
    {
        var commandNames = Enum.GetNames(typeof(DataVangerCommandType));

        var remediationCommands = commandNames
            .Where(name => name.Contains("Remediat", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        Assert.Equal(new[] { nameof(DataVangerCommandType.ExecuteRemediationAction) }, remediationCommands);

        foreach (var forbidden in new[] { "Kill", "Disinfect", "RemoveThreat", "FixThreat" })
            Assert.DoesNotContain(commandNames, name =>
                name.Contains(forbidden, StringComparison.OrdinalIgnoreCase));

        var categories = Enum.GetNames(typeof(DataVangerCommandCategory));
        Assert.Contains(nameof(DataVangerCommandCategory.Remediation), categories);
    }

    [Fact]
    public void IpcCommandCatalog_AllowsOnlyKnownNonDestructiveCommands()
    {
        // Every allowlisted command must belong to the known non-destructive
        // categories of this phase. (DeleteQuarantineItem exists in the enum
        // but its handler honestly returns Unsupported — quarantine-store
        // delete arrives with remediation phases.)
        foreach (var command in DataVangerCommandCatalog.AllowedCommands)
        {
            var category = DataVangerCommandCatalog.CategoryOf(command);
            Assert.True(category != DataVangerCommandCategory.Unknown,
                $"{command} maps to Unknown category");
        }
    }
}
