namespace DataVanger.Shared.Updates;

/// <summary>
/// Operating mode of the signed-update subsystem.
///
/// Anti-FP / safety note: none of these modes can produce a malware
/// verdict. Update activity is operational telemetry only. The mode
/// controls *whether* updates are checked/applied and *which* transport
/// and key trust assumptions apply — never classification.
/// </summary>
public enum UpdateMode
{
    /// <summary>No update activity at all. Emits no events.</summary>
    Disabled = 0,

    /// <summary>Check and apply only on an explicit call.</summary>
    ManualOnly = 1,

    /// <summary>Check for updates and emit status, but never apply.</summary>
    PassiveCheck = 2,

    /// <summary>Automatically apply signed, non-executable feeds only.</summary>
    AutoApplyFeedsOnly = 3,

    /// <summary>
    /// Development mode: trusts test keys, requires no network, and is the
    /// only mode (with <see cref="Test"/>) where a downgrade override may be
    /// honored when explicitly enabled.
    /// </summary>
    Development = 4,

    /// <summary>
    /// Test mode: in-memory transport and deterministic key fixtures only.
    /// </summary>
    Test = 5,
}
