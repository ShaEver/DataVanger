using System;
using DataVanger.Core;

namespace DataVanger.Settings;

/// <summary>
/// An editable boolean setting: its <see cref="SettingMetadata"/> plus typed
/// get/set accessors onto the existing <see cref="AppSettings"/>. The accessors
/// read and write the real stored field, so values round-trip without loss and
/// nothing is renamed or migrated destructively.
/// </summary>
public sealed class ToggleSetting
{
    private readonly Func<AppSettings, bool> _get;
    private readonly Action<AppSettings, bool> _set;

    public ToggleSetting(SettingMetadata meta, Func<AppSettings, bool> getter, Action<AppSettings, bool> setter)
    {
        Meta = meta ?? throw new ArgumentNullException(nameof(meta));
        _get = getter ?? throw new ArgumentNullException(nameof(getter));
        _set = setter ?? throw new ArgumentNullException(nameof(setter));
    }

    public SettingMetadata Meta { get; }

    public bool Get(AppSettings settings) => _get(settings);

    public void Set(AppSettings settings, bool value) => _set(settings, value);

    /// <summary>
    /// Disabling a protection setting (true → false) requires confirmation;
    /// re-enabling (→ true) never does; a non-protection toggle never does. This is
    /// the single source of the confirm-on-disable rule, unit-tested independently
    /// of any UI.
    /// </summary>
    public bool RequiresDisableConfirmation(bool currentValue, bool newValue)
        => Meta.ConfirmOnDisable && currentValue && !newValue;
}
