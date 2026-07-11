namespace DataVanger.Shared.Service;

/// <summary>
/// Honest availability labels for runtime modules surfaced by the service
/// host. Phase 2 Step 02 deliberately registers protection modules as
/// passive / not-implemented placeholders — they must never be reported
/// as active protection.
/// </summary>
public enum RuntimeModuleAvailability
{
    Available = 0,
    Unavailable = 1,
    Disabled = 2,
    Passive = 3,
    Degraded = 4,
    NotImplemented = 5,
}
