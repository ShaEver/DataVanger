namespace DataVanger.Shared.RuntimeEvents;

/// <summary>
/// Operating mode for the runtime event pipeline.
///
///   - <see cref="Disabled"/>: published events are dropped and counted;
///     consumers receive nothing. Used to fully neutralize the pipeline
///     without removing wiring.
///
///   - <see cref="Development"/>: deterministic, development-safe
///     default. Events flow inline to subscribers; no background loops,
///     no admin requirement, no file locking, no protected-system writes.
///
///   - <see cref="Passive"/>: events flow to consumers for observation
///     and reporting only. Consumers MUST NOT take active remediation
///     in this mode.
///
///   - <see cref="Active"/>: events flow to consumers; remediation-
///     capable consumers may act ONLY when an action is independently
///     authorized by the existing classification policy (e.g.
///     ConfirmedMalware quarantine). The pipeline itself never
///     authorizes remediation.
/// </summary>
public enum RuntimeEventPipelineMode
{
    Disabled = 0,
    Development,
    Passive,
    Active,
}
