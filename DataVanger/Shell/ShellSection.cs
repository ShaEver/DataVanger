namespace DataVanger.Shell;

/// <summary>
/// Beta navigation shell sections (phase 01A). Internal names follow the
/// Evolution Plan screen list; the Removal Center is intentionally absent
/// until remediation phases 03/04 exist.
/// </summary>
public enum ShellSection
{
    Dashboard,
    Scan,
    Protection,
    Threats,
    Quarantine,
    Reports,
    Updates,
    Settings,
    Diagnostics,
}

/// <summary>
/// How a navigation item behaves when selected.
/// Hosted sections swap the content region; Launcher sections open an
/// existing Alpha modal window through its unchanged code path and do not
/// change the current selection.
/// </summary>
public enum ShellSectionKind
{
    Hosted,
    Launcher,
}
