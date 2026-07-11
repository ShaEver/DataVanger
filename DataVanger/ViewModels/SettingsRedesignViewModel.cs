using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using DataVanger.Core;
using DataVanger.Settings;

namespace DataVanger.ViewModels;

/// <summary>
/// WPF-free view model for the redesigned, grouped settings experience (Phase 06).
/// It wraps an existing <see cref="AppSettings"/> and exposes its boolean settings
/// grouped, plain-language, and gated by a reveal tier, with a confirm-on-disable
/// rule for protection settings. It changes no defaults, no thresholds, and no
/// persisted keys — saving round-trips through the unchanged <see cref="AppSettings"/>
/// loader. Named distinctly from the Shared <c>SettingsViewModel</c> record to avoid
/// any namespace ambiguity.
/// </summary>
public sealed class SettingsRedesignViewModel : INotifyPropertyChanged
{
    private readonly AppSettings _settings;
    private SettingVisibility _revealLevel = SettingVisibility.Normal;

    public SettingsRedesignViewModel(AppSettings settings)
        => _settings = settings ?? throw new ArgumentNullException(nameof(settings));

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>The backing settings (e.g. for saving). Never replaced.</summary>
    public AppSettings Settings => _settings;

    public SettingVisibility RevealLevel
    {
        get => _revealLevel;
        set
        {
            if (_revealLevel == value) return;
            _revealLevel = value;
            OnPropertyChanged(nameof(RevealLevel));
            OnPropertyChanged(nameof(ShowAdvanced));
            OnPropertyChanged(nameof(ShowDeveloper));
            OnPropertyChanged(nameof(VisibleToggles));
        }
    }

    public bool ShowAdvanced => _revealLevel >= SettingVisibility.Advanced;
    public bool ShowDeveloper => _revealLevel >= SettingVisibility.Developer;

    /// <summary>True when a setting at the given visibility is revealed at the
    /// current level. Developer/experimental settings are never visible to Normal
    /// users.</summary>
    public bool IsVisible(SettingVisibility visibility) => (int)visibility <= (int)_revealLevel;

    /// <summary>Editable toggles visible at the current reveal level.</summary>
    public IReadOnlyList<ToggleSetting> VisibleToggles =>
        SettingsCatalog.Toggles.Where(t => IsVisible(t.Meta.Visibility)).ToArray();

    /// <summary>Visible toggles grouped by category, in group order.</summary>
    public IReadOnlyList<IGrouping<SettingGroup, ToggleSetting>> VisibleGroups =>
        VisibleToggles.GroupBy(t => t.Meta.Group).OrderBy(g => (int)g.Key).ToArray();

    public bool GetValue(ToggleSetting toggle)
        => (toggle ?? throw new ArgumentNullException(nameof(toggle))).Get(_settings);

    /// <summary>Whether changing <paramref name="toggle"/> to <paramref name="newValue"/>
    /// must be confirmed first (disabling a protection setting). Callers MUST honour
    /// this before applying — the UI must never lower protection silently.</summary>
    public bool RequiresDisableConfirmation(ToggleSetting toggle, bool newValue)
        => (toggle ?? throw new ArgumentNullException(nameof(toggle)))
            .RequiresDisableConfirmation(toggle.Get(_settings), newValue);

    /// <summary>Apply a toggle value to the backing settings. The caller is
    /// responsible for having confirmed when <see cref="RequiresDisableConfirmation"/>
    /// is true.</summary>
    public void SetValue(ToggleSetting toggle, bool newValue)
        => (toggle ?? throw new ArgumentNullException(nameof(toggle))).Set(_settings, newValue);

    /// <summary>Persist via the unchanged AppSettings saver (additive schema, lossless).</summary>
    public void Save(string path) => _settings.Save(path);

    private void OnPropertyChanged(string name)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
