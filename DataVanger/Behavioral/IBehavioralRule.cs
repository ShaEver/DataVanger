using System.Collections.Generic;
using DataVanger.Core;

namespace DataVanger.Behavioral;

/// <summary>
/// Pure-logic behavioral rule.
///
/// Rules receive an event plus read-only views of the ancestry and
/// timeline. They return ZERO or MORE <see cref="Evidence"/> records to
/// contribute to the engine's accumulated correlation score.
///
/// Rules MUST be deterministic, side-effect free, and quick (no IO).
/// Anything stateful belongs in the timeline / ancestry, not the rule.
/// </summary>
public interface IBehavioralRule
{
    /// <summary>Stable rule identifier — used for telemetry and dedup.</summary>
    string RuleId { get; }

    /// <summary>Short human-readable description used in evidence.</summary>
    string Title { get; }

    IReadOnlyList<Evidence> Evaluate(
        BehavioralEvent ev,
        ProcessAncestry ancestry,
        BehavioralTimeline timeline);
}
