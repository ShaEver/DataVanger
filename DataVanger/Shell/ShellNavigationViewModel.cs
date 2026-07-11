using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;

namespace DataVanger.Shell;

/// <summary>
/// Navigation state for the Beta shell (phase 01A). Deliberately tiny and
/// WPF-free: it tracks which section is selected and tells the view when a
/// launcher item (existing Alpha modal) was requested. It never touches
/// engine, service, quarantine, update or remediation code — navigation is
/// cosmetic/structural only, per the phase safety rules.
/// </summary>
public sealed class ShellNavigationViewModel : INotifyPropertyChanged
{
    private ShellSection _selectedSection = ShellSection.Dashboard;

    public ShellNavigationViewModel()
    {
        Items = new List<ShellNavigationItem>
        {
            new(ShellSection.Dashboard,   ShellLabels.Dashboard,   ShellSectionKind.Hosted),
            new(ShellSection.Scan,        ShellLabels.Scan,        ShellSectionKind.Hosted),
            new(ShellSection.Protection,  ShellLabels.Protection,  ShellSectionKind.Hosted),
            new(ShellSection.Threats,     ShellLabels.Threats,     ShellSectionKind.Hosted),
            new(ShellSection.Quarantine,  ShellLabels.Quarantine,  ShellSectionKind.Launcher),
            new(ShellSection.Reports,     ShellLabels.Reports,     ShellSectionKind.Hosted),
            new(ShellSection.Updates,     ShellLabels.Updates,     ShellSectionKind.Hosted),
            new(ShellSection.Settings,    ShellLabels.Settings,    ShellSectionKind.Launcher),
            new(ShellSection.Diagnostics, ShellLabels.Diagnostics, ShellSectionKind.Hosted),
        };
        SyncSelectionFlags();
    }

    public IReadOnlyList<ShellNavigationItem> Items { get; }

    /// <summary>Raised when a Launcher item is activated. The view maps the
    /// section to the existing Alpha handler (same code path as the legacy
    /// sidebar button). Selection does not change for launchers.</summary>
    public event Action<ShellSection>? LauncherRequested;

    public ShellSection SelectedSection
    {
        get => _selectedSection;
        private set
        {
            if (_selectedSection == value) return;
            _selectedSection = value;
            SyncSelectionFlags();
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SelectedSection)));
        }
    }

    /// <summary>
    /// Activates a section. Hosted sections become the current selection and
    /// return true; Launcher sections raise <see cref="LauncherRequested"/>
    /// and return false, leaving the current selection untouched.
    /// </summary>
    public bool TrySelect(ShellSection section)
    {
        var item = Items.FirstOrDefault(i => i.Section == section);
        if (item is null) return false;

        if (item.Kind == ShellSectionKind.Launcher)
        {
            LauncherRequested?.Invoke(section);
            return false;
        }

        SelectedSection = section;
        return true;
    }

    private void SyncSelectionFlags()
    {
        foreach (var item in Items)
            item.IsSelected = item.Section == _selectedSection;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}
