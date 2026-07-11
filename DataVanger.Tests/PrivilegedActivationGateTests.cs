using System;
using System.IO;
using DataVanger.Service.Hosting;
using Xunit;

namespace DataVanger.Tests;

public sealed class PrivilegedActivationGateTests
{
    [Fact]
    public void Install_IsFailClosed_BeforeAnySystemOperation()
    {
        var output = new StringWriter();
        var error = new StringWriter();

        int code = WindowsServiceInstaller.Install(output, error, @"C:\unsafe\service.json");

        Assert.Equal(WindowsServiceInstaller.ExitSecureInstallerUnavailable, code);
        Assert.Contains("unavailable until a secure installer", error.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("No service was registered", error.ToString(), StringComparison.Ordinal);
        Assert.Empty(output.ToString());
    }

    [Fact]
    public void AmsiRegistration_IsFailClosed_BeforeAnySystemOperation()
    {
        var output = new StringWriter();
        var error = new StringWriter();

        int code = AmsiProviderRegistration.Register(output, error, @"C:\unsafe\provider.dll");

        Assert.Equal(AmsiProviderRegistration.ExitSecureInstallerUnavailable, code);
        Assert.Contains("unavailable until a secure installer", error.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("No provider was registered", error.ToString(), StringComparison.Ordinal);
        Assert.Empty(output.ToString());
    }

    [Theory]
    [InlineData(@"C:\Windows\Temp\DataVanger.Service.exe")]
    [InlineData(@"C:\Users\operator\Downloads\DataVanger.Service.exe")]
    [InlineData(@"C:\Users\operator\DataVanger.Service.exe")]
    public void FuturePolicy_RejectsArtifactsOutsideProtectedRoot(string path)
    {
        var policy = NewPolicy(new FakeInstallationSecurityProbes());

        Assert.False(policy.TryValidate(path, InstallationArtifactKind.ServiceExecutable, out var reason));
        Assert.Contains("outside", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(@"relative\DataVanger.Service.exe")]
    [InlineData(@"\\server\share\DataVanger.Service.exe")]
    [InlineData(@"C:\Program Files\DataVanger\DataVanger.Service.exe:payload")]
    [InlineData(@"C:\Program Files\DataVanger\sub\..\DataVanger.Service.exe")]
    public void FuturePolicy_RejectsUnsafePathForms(string path)
    {
        var policy = NewPolicy(new FakeInstallationSecurityProbes());

        Assert.False(policy.TryValidate(path, InstallationArtifactKind.ServiceExecutable, out _));
    }

    [Fact]
    public void FuturePolicy_AcceptsProtectedArtifact_OnlyWhenEveryProbeApproves()
    {
        var probes = new FakeInstallationSecurityProbes();
        var policy = NewPolicy(probes);
        const string artifact = @"C:\Program Files\DataVanger\DataVanger.Service.exe";

        Assert.True(policy.TryValidate(artifact, InstallationArtifactKind.ServiceExecutable, out var reason), reason);

        probes.ProtectedRoot = false;
        Assert.False(policy.TryValidate(artifact, InstallationArtifactKind.ServiceExecutable, out _));
        probes.ProtectedRoot = true;
        probes.Reparse = true;
        Assert.False(policy.TryValidate(artifact, InstallationArtifactKind.ServiceExecutable, out _));
        probes.Reparse = false;
        probes.UnprivilegedWritable = true;
        Assert.False(policy.TryValidate(artifact, InstallationArtifactKind.ServiceExecutable, out _));
        probes.UnprivilegedWritable = false;
        probes.ExpectedSignature = false;
        Assert.False(policy.TryValidate(artifact, InstallationArtifactKind.ServiceExecutable, out _));
    }

    [Fact]
    public void FuturePolicy_RejectsConfigurationOutsideProtectedRoot()
    {
        var policy = NewPolicy(new FakeInstallationSecurityProbes());

        Assert.False(policy.TryValidate(
            @"C:\ProgramData\DataVanger\service.json",
            InstallationArtifactKind.Configuration,
            out var reason));
        Assert.Contains("outside", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Uninstall_IsAdminGated_AndMissingServiceIsIdempotent()
    {
        var notElevated = new FakeServiceRecoveryOperations { IsElevated = false };
        Assert.Equal(WindowsServiceInstaller.ExitNotElevated,
            WindowsServiceInstaller.Uninstall(new StringWriter(), new StringWriter(), notElevated));
        Assert.Equal(0, notElevated.Calls);

        var absent = new FakeServiceRecoveryOperations
        {
            StopResult = RecoveryOperationResult.NotFound,
            DeleteResult = RecoveryOperationResult.NotFound,
        };
        Assert.Equal(WindowsServiceInstaller.ExitOk,
            WindowsServiceInstaller.Uninstall(new StringWriter(), new StringWriter(), absent));
        Assert.Equal(WindowsServiceInstaller.ExitOk,
            WindowsServiceInstaller.Uninstall(new StringWriter(), new StringWriter(), absent));
        Assert.Equal(4, absent.Calls);
    }

    [Fact]
    public void AmsiUnregister_IsAdminGated_AndMissingRegistrationIsIdempotent()
    {
        var notElevated = new FakeAmsiRecoveryOperations { IsElevated = false };
        Assert.Equal(AmsiProviderRegistration.ExitNotElevated,
            AmsiProviderRegistration.Unregister(new StringWriter(), new StringWriter(), notElevated));
        Assert.Equal(0, notElevated.Calls);

        var absent = new FakeAmsiRecoveryOperations { Result = RecoveryOperationResult.NotFound };
        Assert.Equal(AmsiProviderRegistration.ExitOk,
            AmsiProviderRegistration.Unregister(new StringWriter(), new StringWriter(), absent));
        Assert.Equal(AmsiProviderRegistration.ExitOk,
            AmsiProviderRegistration.Unregister(new StringWriter(), new StringWriter(), absent));
        Assert.Equal(2, absent.Calls);
    }

    private static PrivilegedInstallationSecurityPolicy NewPolicy(IInstallationSecurityProbes probes)
        => new(@"C:\Program Files\DataVanger", "DataVanger Security", "AA BB CC", probes);

    private sealed class FakeInstallationSecurityProbes : IInstallationSecurityProbes
    {
        public bool Exists { get; set; } = true;
        public bool ProtectedRoot { get; set; } = true;
        public bool Reparse { get; set; }
        public bool UnprivilegedWritable { get; set; }
        public bool ExpectedSignature { get; set; } = true;

        public bool FileExists(string path) => Exists;
        public bool IsProtectedInstallationRoot(string rootPath) => ProtectedRoot;
        public bool HasReparsePoint(string path) => Reparse;
        public bool IsWritableByUnprivilegedUsers(string path) => UnprivilegedWritable;
        public bool HasExpectedSignature(string path, string expectedPublisher, string expectedThumbprint)
            => ExpectedSignature && expectedPublisher == "DataVanger Security" && expectedThumbprint == "AABBCC";
    }

    private sealed class FakeServiceRecoveryOperations : IServiceRecoveryOperations
    {
        public bool IsSupportedPlatform { get; set; } = true;
        public bool IsElevated { get; set; } = true;
        public RecoveryOperationResult StopResult { get; set; } = RecoveryOperationResult.Success;
        public RecoveryOperationResult DeleteResult { get; set; } = RecoveryOperationResult.Success;
        public int Calls { get; private set; }

        public RecoveryOperationResult StopService(TextWriter output, TextWriter error)
        {
            Calls++;
            return StopResult;
        }

        public RecoveryOperationResult DeleteService(TextWriter output, TextWriter error)
        {
            Calls++;
            return DeleteResult;
        }
    }

    private sealed class FakeAmsiRecoveryOperations : IAmsiRegistrationRecoveryOperations
    {
        public bool IsSupportedPlatform { get; set; } = true;
        public bool IsElevated { get; set; } = true;
        public RecoveryOperationResult Result { get; set; } = RecoveryOperationResult.Success;
        public int Calls { get; private set; }

        public RecoveryOperationResult RemoveRegistration(string providerClsid)
        {
            Calls++;
            return Result;
        }
    }
}
