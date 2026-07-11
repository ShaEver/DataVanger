namespace DataVanger.Behavioral;

/// <summary>
/// Taxonomy of behavioral event kinds.
///
/// Kinds describe what happened, NOT how risky it is. Severity is a
/// separate dimension (see <see cref="BehavioralSeverity"/>) so the same
/// event kind can be reported with different severities depending on
/// rule context.
/// </summary>
public enum BehavioralEventKind
{
    /// <summary>Sentinel value — not a real event.</summary>
    None = 0,

    ProcessStart,
    ProcessEnd,
    ScriptExecution,
    LolbinInvocation,
    EncodedPayload,
    PersistenceCreated,
    PersistenceModified,
    FileDropped,
    RegistryModified,
    SecurityTamperIndicator,
    AmsiBypassIndicator,
    InjectionIndicator,
    NetworkConnect,
    CredentialAccessIndicator,
    OfficeSpawnsScript,
}
