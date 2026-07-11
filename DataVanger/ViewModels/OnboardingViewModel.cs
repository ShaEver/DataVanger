using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using DataVanger.Core;

namespace DataVanger.ViewModels;

/// <summary>
/// WPF-free first-run onboarding state (Phase 07). It presents conservative,
/// recommended defaults and applies them to <see cref="AppSettings"/> without ever
/// weakening protection: onboarding can only turn protections ON. First-run is
/// tracked with a marker file, so no <see cref="AppSettings"/> schema change is
/// needed. The UI binds to it; the logic is unit-tested without a UI host.
/// </summary>
public sealed class OnboardingViewModel : INotifyPropertyChanged
{
    private readonly AppSettings _settings;
    private bool _enableRealtimeProtection;
    private bool _autoQuarantineKnownMalware;
    private bool _startWithWindows;

    public OnboardingViewModel(AppSettings settings)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));

        // Recommended, conservative defaults. Real-time protection is recommended
        // ON; auto-quarantine starts from the (already conservative) current value;
        // "start with Windows" is opt-in (OFF) so onboarding adds nothing silently.
        _enableRealtimeProtection = true;
        _autoQuarantineKnownMalware = _settings.AutoQuarantineKnownMalware;
        _startWithWindows = false;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public bool EnableRealtimeProtection
    {
        get => _enableRealtimeProtection;
        set => SetField(ref _enableRealtimeProtection, value);
    }

    public bool AutoQuarantineKnownMalware
    {
        get => _autoQuarantineKnownMalware;
        set => SetField(ref _autoQuarantineKnownMalware, value);
    }

    public bool StartWithWindows
    {
        get => _startWithWindows;
        set => SetField(ref _startWithWindows, value);
    }

    /// <summary>The "start with Windows" preference. Applying it to the OS (startup
    /// entry) is a separate, Windows-only step; this view model only records intent.</summary>
    public bool StartWithWindowsPreference => _startWithWindows;

    /// <summary>
    /// Apply the chosen options to <paramref name="settings"/>. Protection-impacting
    /// settings are only ever ENABLED here — onboarding never disables a protection
    /// (that requires the Settings confirm-on-disable flow). So real-time protection
    /// and auto-quarantine are turned on when chosen, and never turned off.
    /// </summary>
    public void ApplyTo(AppSettings settings)
    {
        if (settings is null) throw new ArgumentNullException(nameof(settings));
        if (_enableRealtimeProtection) settings.EnableTrayProtection = true;
        if (_autoQuarantineKnownMalware) settings.AutoQuarantineKnownMalware = true;
        // Note: never set these to false here — onboarding cannot weaken protection.
    }

    /// <summary>Apply to the backing settings and persist them.</summary>
    public void CompleteAndSave(string settingsPath)
    {
        ApplyTo(_settings);
        _settings.Save(settingsPath);
    }

    /// <summary>First run when the onboarding marker does not yet exist.</summary>
    public static bool IsFirstRun(string markerPath)
        => string.IsNullOrEmpty(markerPath) || !File.Exists(markerPath);

    /// <summary>Record that onboarding has completed (best-effort, never throws to
    /// the caller).</summary>
    public static void MarkOnboardingComplete(string markerPath)
    {
        if (string.IsNullOrEmpty(markerPath)) return;
        try
        {
            var dir = Path.GetDirectoryName(markerPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(markerPath, DateTimeOffset.UtcNow.ToString("O"));
        }
        catch (IOException)
        {
            // Marker is best-effort; onboarding still completed for this session.
        }
        catch (UnauthorizedAccessException)
        {
            // No permission to write the marker; onboarding may re-show next launch.
        }
    }

    private void SetField(ref bool field, bool value, [CallerMemberName] string? name = null)
    {
        if (field == value) return;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
