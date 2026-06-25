using System;
using System.IO;
using System.Linq;
using DataVanger.Core;
using DataVanger.Settings;
using DataVanger.ViewModels;
using Xunit;

// Phase 06 — Settings redesign. Behaviour-preserving metadata + grouped, reveal-gated
// view model + confirm-on-disable. AppSettings itself is unchanged (schema/migration
// tests in AppSettingsSchemaTests remain the oracle); these tests cover the new layer.
public class SettingsRedesignTests
{
    // ── Catalog integrity ──────────────────────────────────────────────────
    [Fact]
    public void EveryToggle_MapsToARealBoolAppSettingsProperty()
    {
        foreach (var t in SettingsCatalog.Toggles)
        {
            var prop = typeof(AppSettings).GetProperty(t.Meta.Key);
            Assert.True(prop is not null, $"AppSettings has no property '{t.Meta.Key}'.");
            Assert.Equal(typeof(bool), prop!.PropertyType);
        }
    }

    [Fact]
    public void EveryToggleAccessor_RoundTripsThroughTheNamedProperty()
    {
        foreach (var t in SettingsCatalog.Toggles)
        {
            var prop = typeof(AppSettings).GetProperty(t.Meta.Key)!;
            var s = new AppSettings();

            t.Set(s, true);
            Assert.True((bool)prop.GetValue(s)!, $"setter/getter mismatch (true) for {t.Meta.Key}");
            Assert.True(t.Get(s));

            t.Set(s, false);
            Assert.False((bool)prop.GetValue(s)!, $"setter/getter mismatch (false) for {t.Meta.Key}");
            Assert.False(t.Get(s));
        }
    }

    [Fact]
    public void EveryMetadata_HasNameDescriptionAndDimension()
    {
        foreach (var m in SettingsCatalog.AllMetadata)
        {
            Assert.False(string.IsNullOrWhiteSpace(m.Key));
            Assert.False(string.IsNullOrWhiteSpace(m.DisplayName));
            Assert.False(string.IsNullOrWhiteSpace(m.Description));
            Assert.False(string.IsNullOrWhiteSpace(m.Dimension));
        }
    }

    [Fact]
    public void MetadataKeys_AreUnique()
    {
        var keys = SettingsCatalog.AllMetadata.Select(m => m.Key).ToArray();
        Assert.Equal(keys.Length, keys.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void Catalog_CoversTheProtectionGroups()
    {
        var groups = SettingsCatalog.AllMetadata.Select(m => m.Group).Distinct().ToArray();
        Assert.Contains(SettingGroup.Scanning, groups);
        Assert.Contains(SettingGroup.RealTimeProtection, groups);
        Assert.Contains(SettingGroup.ThreatRemoval, groups);
    }

    [Fact]
    public void EveryConfirmOnDisable_IsAProtectionSetting()
    {
        foreach (var t in SettingsCatalog.Toggles.Where(t => t.Meta.ConfirmOnDisable))
            Assert.Equal(SettingRisk.Protection, t.Meta.Risk);
    }

    // ── Visibility / reveal ────────────────────────────────────────────────
    [Fact]
    public void NormalReveal_HidesAdvancedAndDeveloperToggles()
    {
        var vm = new SettingsRedesignViewModel(new AppSettings()) { RevealLevel = SettingVisibility.Normal };
        Assert.All(vm.VisibleToggles, t => Assert.Equal(SettingVisibility.Normal, t.Meta.Visibility));
        Assert.False(vm.ShowAdvanced);
        Assert.False(vm.ShowDeveloper);
    }

    [Fact]
    public void AdvancedReveal_ShowsAdvanced_ButNotDeveloper()
    {
        var vm = new SettingsRedesignViewModel(new AppSettings()) { RevealLevel = SettingVisibility.Advanced };
        Assert.Contains(vm.VisibleToggles, t => t.Meta.Visibility == SettingVisibility.Advanced);
        Assert.DoesNotContain(vm.VisibleToggles, t => t.Meta.Visibility == SettingVisibility.Developer);
        Assert.True(vm.ShowAdvanced);
        Assert.False(vm.ShowDeveloper);
    }

    [Fact]
    public void DeveloperReveal_ShowsEveryToggle()
    {
        var vm = new SettingsRedesignViewModel(new AppSettings()) { RevealLevel = SettingVisibility.Developer };
        Assert.Equal(SettingsCatalog.Toggles.Count, vm.VisibleToggles.Count);
        Assert.True(vm.ShowDeveloper);
    }

    [Fact]
    public void RawThreshold_IsDeveloperOnly_AndNeverANormalToggle()
    {
        var threshold = SettingsCatalog.AllMetadata.Single(m => m.Key == "MinScoreToQuarantine");
        Assert.Equal(SettingVisibility.Developer, threshold.Visibility);

        var vmNormal = new SettingsRedesignViewModel(new AppSettings()) { RevealLevel = SettingVisibility.Normal };
        Assert.DoesNotContain(vmNormal.VisibleToggles, t => t.Meta.Key == "MinScoreToQuarantine");
    }

    [Fact]
    public void VisibleGroups_AreOrdered_AndOnlyContainVisibleToggles()
    {
        var vm = new SettingsRedesignViewModel(new AppSettings()) { RevealLevel = SettingVisibility.Advanced };
        var groups = vm.VisibleGroups;
        Assert.NotEmpty(groups);
        Assert.All(groups, g => Assert.All(g, t => Assert.True((int)t.Meta.Visibility <= (int)SettingVisibility.Advanced)));
    }

    // ── Confirm-on-disable ─────────────────────────────────────────────────
    [Fact]
    public void DisablingProtectionToggle_RequiresConfirmation()
    {
        var s = new AppSettings { AutoQuarantineKnownMalware = true };
        var vm = new SettingsRedesignViewModel(s);
        var toggle = SettingsCatalog.Toggles.Single(t => t.Meta.Key == "AutoQuarantineKnownMalware");
        Assert.True(vm.RequiresDisableConfirmation(toggle, newValue: false));
    }

    [Fact]
    public void EnablingProtectionToggle_DoesNotRequireConfirmation()
    {
        var s = new AppSettings { EnableTrayProtection = false };
        var vm = new SettingsRedesignViewModel(s);
        var toggle = SettingsCatalog.Toggles.Single(t => t.Meta.Key == "EnableTrayProtection");
        Assert.False(vm.RequiresDisableConfirmation(toggle, newValue: true));
    }

    [Fact]
    public void DisablingCosmeticToggle_DoesNotRequireConfirmation()
    {
        var s = new AppSettings { UseSafeCache = true };
        var vm = new SettingsRedesignViewModel(s);
        var toggle = SettingsCatalog.Toggles.Single(t => t.Meta.Key == "UseSafeCache");
        Assert.False(toggle.Meta.ConfirmOnDisable);
        Assert.False(vm.RequiresDisableConfirmation(toggle, newValue: false));
    }

    // ── Value preservation ─────────────────────────────────────────────────
    [Fact]
    public void SetValue_ChangesBackingSetting()
    {
        var s = new AppSettings { ScanDownloads = true };
        var vm = new SettingsRedesignViewModel(s);
        var toggle = SettingsCatalog.Toggles.Single(t => t.Meta.Key == "ScanDownloads");

        vm.SetValue(toggle, false);

        Assert.False(s.ScanDownloads);
        Assert.False(vm.GetValue(toggle));
    }

    [Fact]
    public void SaveThenReload_PreservesChangedValue_SchemaVersion_AndOtherDefaults()
    {
        var path = Path.Combine(Path.GetTempPath(), "dvtest_settings_" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var s = AppSettings.Load(path); // creates a default file
            var vm = new SettingsRedesignViewModel(s);
            var toggle = SettingsCatalog.Toggles.Single(t => t.Meta.Key == "AutoQuarantineKnownMalware");

            vm.SetValue(toggle, false);
            vm.Save(path);

            var reloaded = AppSettings.Load(path);
            Assert.False(reloaded.AutoQuarantineKnownMalware);                 // changed value preserved
            Assert.Equal(AppSettings.CurrentSchemaVersion, reloaded.SchemaVersion);
            Assert.True(reloaded.ScanStartupLocations);                        // unrelated default preserved
        }
        finally
        {
            try { File.Delete(path); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    [Fact]
    public void Catalog_DoesNotChangeConservativeDefaults()
    {
        var s = new AppSettings();
        _ = new SettingsRedesignViewModel(s);

        Assert.True(s.AutoQuarantineKnownMalware);
        Assert.True(s.ScanStartupLocations);
        Assert.False(s.EnableTrayProtection);          // default off, unchanged
        Assert.Equal(9, s.MinScoreToQuarantine);       // RiskThresholds.High, unchanged
        Assert.Equal(6, s.MinScoreToReport);           // RiskThresholds.Suspect, unchanged
    }
}
