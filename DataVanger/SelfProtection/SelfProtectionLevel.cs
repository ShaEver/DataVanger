namespace DataVanger.SelfProtection;

/// <summary>
/// Protection level dial. See 09_SELF_PROTECTION.md for the full taxonomy.
///
///   - <see cref="Off"/>      : everything disabled. Manager is a no-op.
///   - <see cref="Basic"/>    : configuration integrity + watchdog observation.
///   - <see cref="Standard"/> : adds runtime/service tamper detection signals.
///   - <see cref="Hardened"/> : maximum strictness for tamper evidence emission.
///
/// The level NEVER changes the verdict pipeline. Self-protection only
/// produces evidence/events; the threat classifier remains the single
/// owner of malware verdicts.
/// </summary>
public enum SelfProtectionLevel
{
    Off = 0,
    Basic = 1,
    Standard = 2,
    Hardened = 3,
}
