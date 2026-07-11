using System.Collections.Generic;
using System.Linq;
using DataVanger.Shell;
using Xunit;

// Beta phase 01A — navigation shell state tests. Runnable via:
//   dotnet test --filter "FullyQualifiedName~ShellNavigation"
// The view model is intentionally WPF-free so these tests need no UI host and
// can assert the phase safety rules: navigation is state-only, launchers never
// change selection, and the Removal Center is absent until phases 03/04.
public class ShellNavigationTests
{
    [Fact]
    public void DefaultSelection_IsDashboard()
    {
        var vm = new ShellNavigationViewModel();

        Assert.Equal(ShellSection.Dashboard, vm.SelectedSection);
        Assert.True(vm.Items.Single(i => i.Section == ShellSection.Dashboard).IsSelected);
        Assert.Equal(1, vm.Items.Count(i => i.IsSelected));
    }

    [Fact]
    public void Items_ExposeExactlyTheNinePlannedSections_InOrder_NoRemovalCenter()
    {
        var vm = new ShellNavigationViewModel();

        var expected = new[]
        {
            ShellSection.Dashboard, ShellSection.Scan, ShellSection.Protection,
            ShellSection.Threats, ShellSection.Quarantine, ShellSection.Reports,
            ShellSection.Updates, ShellSection.Settings, ShellSection.Diagnostics,
        };

        Assert.Equal(expected, vm.Items.Select(i => i.Section).ToArray());
        Assert.Equal(vm.Items.Count, vm.Items.Select(i => i.Section).Distinct().Count());
        Assert.All(vm.Items, i => Assert.False(string.IsNullOrWhiteSpace(i.Label)));
    }

    [Fact]
    public void TrySelect_HostedSection_UpdatesSelectionAndFlags()
    {
        var vm = new ShellNavigationViewModel();

        bool moved = vm.TrySelect(ShellSection.Reports);

        Assert.True(moved);
        Assert.Equal(ShellSection.Reports, vm.SelectedSection);
        Assert.True(vm.Items.Single(i => i.Section == ShellSection.Reports).IsSelected);
        Assert.False(vm.Items.Single(i => i.Section == ShellSection.Dashboard).IsSelected);
        Assert.Equal(1, vm.Items.Count(i => i.IsSelected));
    }

    [Fact]
    public void TrySelect_Launcher_RaisesEventAndKeepsSelection()
    {
        var vm = new ShellNavigationViewModel();
        var launched = new List<ShellSection>();
        vm.LauncherRequested += launched.Add;

        bool movedQuarantine = vm.TrySelect(ShellSection.Quarantine);
        bool movedSettings = vm.TrySelect(ShellSection.Settings);

        Assert.False(movedQuarantine);
        Assert.False(movedSettings);
        Assert.Equal(new[] { ShellSection.Quarantine, ShellSection.Settings }, launched);
        Assert.Equal(ShellSection.Dashboard, vm.SelectedSection);
        Assert.True(vm.Items.Single(i => i.Section == ShellSection.Dashboard).IsSelected);
    }

    [Fact]
    public void LauncherKinds_AreExactlyQuarantineAndSettings()
    {
        var vm = new ShellNavigationViewModel();

        var launchers = vm.Items.Where(i => i.Kind == ShellSectionKind.Launcher)
                                .Select(i => i.Section).ToArray();

        Assert.Equal(new[] { ShellSection.Quarantine, ShellSection.Settings }, launchers);
    }

    [Fact]
    public void SelectedSection_RaisesPropertyChanged_OnlyOnRealChange()
    {
        var vm = new ShellNavigationViewModel();
        int raised = 0;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ShellNavigationViewModel.SelectedSection)) raised++;
        };

        vm.TrySelect(ShellSection.Scan);      // change -> 1
        vm.TrySelect(ShellSection.Scan);      // no change -> still 1
        vm.TrySelect(ShellSection.Quarantine); // launcher -> still 1

        Assert.Equal(1, raised);
        Assert.Equal(ShellSection.Scan, vm.SelectedSection);
    }
}
