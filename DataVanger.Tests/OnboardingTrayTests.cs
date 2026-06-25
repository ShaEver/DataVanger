using System;
using System.IO;
using DataVanger.Core;
using DataVanger.ViewModels;
using Xunit;

// Phase 07 — onboarding state (conservative defaults, never weakens protection)
// and tray status derivation.
public class OnboardingTrayTests
{
    // ── Onboarding ─────────────────────────────────────────────────────────
    [Fact]
    public void RecommendedDefaults_AreConservative()
    {
        var vm = new OnboardingViewModel(new AppSettings());
        Assert.True(vm.EnableRealtimeProtection);    // recommend protection ON
        Assert.False(vm.StartWithWindows);           // opt-in, nothing added silently
    }

    [Fact]
    public void ApplyTo_EnablesRealtimeProtection_WhenChosen()
    {
        var settings = new AppSettings { EnableTrayProtection = false };
        var vm = new OnboardingViewModel(settings) { EnableRealtimeProtection = true };

        vm.ApplyTo(settings);

        Assert.True(settings.EnableTrayProtection);
    }

    [Fact]
    public void ApplyTo_NeverDisablesAutoQuarantine()
    {
        var settings = new AppSettings { AutoQuarantineKnownMalware = true };
        // Even if the onboarding flag is off, ApplyTo must not turn protection off.
        var vm = new OnboardingViewModel(settings) { AutoQuarantineKnownMalware = false };

        vm.ApplyTo(settings);

        Assert.True(settings.AutoQuarantineKnownMalware);
    }

    [Fact]
    public void IsFirstRun_TrueWhenMarkerAbsent_FalseAfterMarked()
    {
        var marker = Path.Combine(Path.GetTempPath(), "dvtest_onboard_" + Guid.NewGuid().ToString("N") + ".done");
        try
        {
            Assert.True(OnboardingViewModel.IsFirstRun(marker));
            OnboardingViewModel.MarkOnboardingComplete(marker);
            Assert.False(OnboardingViewModel.IsFirstRun(marker));
        }
        finally
        {
            try { File.Delete(marker); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    [Fact]
    public void CompleteAndSave_PersistsEnabledProtection()
    {
        var path = Path.Combine(Path.GetTempPath(), "dvtest_onboard_settings_" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var settings = AppSettings.Load(path);
            settings.EnableTrayProtection = false;
            var vm = new OnboardingViewModel(settings) { EnableRealtimeProtection = true };

            vm.CompleteAndSave(path);

            var reloaded = AppSettings.Load(path);
            Assert.True(reloaded.EnableTrayProtection);
        }
        finally
        {
            try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    // ── Tray status ────────────────────────────────────────────────────────
    [Fact]
    public void Tray_AllGreen_IsProtected()
    {
        Assert.Equal(TrayStatus.Protected,
            TrayStatusModel.Derive(realtimeActive: true, pendingThreats: false, serviceDegraded: false, updateAvailable: false, remediationInProgress: false));
    }

    [Fact]
    public void Tray_PendingThreats_IsActionNeeded_HighestPriority()
    {
        // Action-needed wins even when other conditions are also present.
        Assert.Equal(TrayStatus.ActionNeeded,
            TrayStatusModel.Derive(realtimeActive: false, pendingThreats: true, serviceDegraded: true, updateAvailable: true, remediationInProgress: true));
    }

    [Fact]
    public void Tray_RealtimeOff_IsDegraded()
    {
        Assert.Equal(TrayStatus.ProtectionDegraded,
            TrayStatusModel.Derive(realtimeActive: false, pendingThreats: false, serviceDegraded: false, updateAvailable: true, remediationInProgress: false));
    }

    [Fact]
    public void Tray_ServiceUnavailable_IsDegraded_EvenWhenRealtimeIsActive()
    {
        Assert.Equal(TrayStatus.ProtectionDegraded,
            TrayStatusModel.Derive(realtimeActive: true, pendingThreats: false, serviceDegraded: true, updateAvailable: false, remediationInProgress: false));
    }

    [Fact]
    public void Tray_RemediationInProgress_OverUpdate()
    {
        Assert.Equal(TrayStatus.RemediationInProgress,
            TrayStatusModel.Derive(realtimeActive: true, pendingThreats: false, serviceDegraded: false, updateAvailable: true, remediationInProgress: true));
    }

    [Fact]
    public void Tray_Describe_IsNonEmpty_AndToastsOnlyForUrgent()
    {
        Assert.False(string.IsNullOrWhiteSpace(TrayStatusModel.Describe(TrayStatus.Protected)));
        Assert.True(TrayStatusModel.ShouldToast(TrayStatus.ActionNeeded));
        Assert.True(TrayStatusModel.ShouldToast(TrayStatus.ProtectionDegraded));
        Assert.False(TrayStatusModel.ShouldToast(TrayStatus.Protected));
        Assert.False(TrayStatusModel.ShouldToast(TrayStatus.UpdateAvailable));
    }
}
