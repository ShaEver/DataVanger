using System;
using DataVanger.Shared.Ipc;
using DataVanger.ViewModels;
using Xunit;

// Phase 07 service-register UX. Honest status + elevation guidance; never installs,
// never elevates, and opening the UI never requires admin.
public class ServiceRegistrationViewModelTests
{
    [Fact]
    public void UiNeverRequiresAdmin()
    {
        var vm = new ServiceRegistrationViewModel(ServiceConnectionStatus.NotInstalled, isCurrentProcessElevated: false);
        Assert.False(vm.UiRequiresAdmin);
    }

    [Fact]
    public void NonElevated_RegistrationRequiresElevation_WithClearInstructions()
    {
        var vm = new ServiceRegistrationViewModel(ServiceConnectionStatus.NotRunning, isCurrentProcessElevated: false);

        Assert.True(vm.RegistrationRequiresElevation);
        Assert.Contains("administrador", vm.ElevationInstructions);
        Assert.False(string.IsNullOrWhiteSpace(vm.StatusSummary));
    }

    [Fact]
    public void Elevated_DoesNotRequireElevation_ToRegister()
    {
        var vm = new ServiceRegistrationViewModel(ServiceConnectionStatus.NotInstalled, isCurrentProcessElevated: true);
        Assert.False(vm.RegistrationRequiresElevation);
    }

    [Theory]
    [InlineData(ServiceConnectionStatus.Connected, true)]
    [InlineData(ServiceConnectionStatus.NotRunning, true)]
    [InlineData(ServiceConnectionStatus.NotInstalled, false)]
    [InlineData(ServiceConnectionStatus.Unknown, false)]
    public void ServiceInstalled_ReflectsStatus(ServiceConnectionStatus status, bool installed)
    {
        var vm = new ServiceRegistrationViewModel(status, isCurrentProcessElevated: false);
        Assert.Equal(installed, vm.ServiceInstalled);
    }

    [Fact]
    public void StatusSummary_IsNonEmpty_ForEveryStatus()
    {
        foreach (ServiceConnectionStatus status in Enum.GetValues(typeof(ServiceConnectionStatus)))
            Assert.False(string.IsNullOrWhiteSpace(
                new ServiceRegistrationViewModel(status, false).StatusSummary));
    }
}
