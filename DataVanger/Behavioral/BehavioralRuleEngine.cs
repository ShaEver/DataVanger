using System;
using System.Collections.Generic;
using DataVanger.Core;

namespace DataVanger.Behavioral;

/// <summary>
/// Evaluates registered rules against an incoming event. Stateless —
/// state lives in the ancestry and timeline passed in.
///
/// The engine catches exceptions per rule so a single broken rule
/// cannot stop the others.
/// </summary>
public sealed class BehavioralRuleEngine
{
    private readonly List<IBehavioralRule> _rules;
    private readonly Action<string>? _diagnostics;

    public BehavioralRuleEngine(IEnumerable<IBehavioralRule> rules, Action<string>? diagnostics = null)
    {
        _rules = new List<IBehavioralRule>(rules ?? Array.Empty<IBehavioralRule>());
        _diagnostics = diagnostics;
    }

    public IReadOnlyList<IBehavioralRule> Rules => _rules;

    public IReadOnlyList<Evidence> Evaluate(BehavioralEvent ev, ProcessAncestry ancestry, BehavioralTimeline timeline)
    {
        if (ev is null) return Array.Empty<Evidence>();
        var aggregated = new List<Evidence>();
        foreach (var rule in _rules)
        {
            try
            {
                var produced = rule.Evaluate(ev, ancestry, timeline);
                if (produced is null) continue;
                foreach (var ev2 in produced)
                {
                    // Defensive contract: NEVER let a rule confirm malware.
                    if (ev2.CanConfirmMalware || ev2.Strength == EvidenceStrength.Confirmed)
                    {
                        aggregated.Add(new Evidence
                        {
                            Category = ev2.Category,
                            Description = ev2.Description,
                            ScoreDelta = ev2.ScoreDelta,
                            Strength = EvidenceStrength.High,
                            CanConfirmMalware = false,
                        });
                    }
                    else
                    {
                        aggregated.Add(ev2);
                    }
                }
            }
            catch (Exception ex)
            {
                try { _diagnostics?.Invoke($"behavioral rule {rule.RuleId} failed: {ex.GetType().Name}: {ex.Message}"); } catch (Exception) { /* Diagnostics sink must never throw back to callers - swallow intentionally. */ }
            }
        }
        return aggregated;
    }
}
