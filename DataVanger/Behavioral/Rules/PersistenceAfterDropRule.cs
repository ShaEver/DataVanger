using System;
using System.Collections.Generic;
using System.Linq;
using DataVanger.Core;

namespace DataVanger.Behavioral.Rules;

/// <summary>
/// Classic loader pattern: a file is dropped (often by a script) and
/// within a short window a persistence entry is created that points to
/// the dropped file (or the same process tree creates a run key /
/// scheduled task / service).
///
/// The rule fires on <see cref="BehavioralEventKind.PersistenceCreated"/>
/// events and looks back into the timeline for a <see cref="BehavioralEventKind.FileDropped"/>
/// event from the same process tree in the last 60 seconds.
/// </summary>
public sealed class PersistenceAfterDropRule : IBehavioralRule
{
    public string RuleId => "B.PERSIST.AfterDrop";
    public string Title => "Persistência criada logo após drop de arquivo executável";

    private static readonly TimeSpan Window = TimeSpan.FromSeconds(60);

    public IReadOnlyList<Evidence> Evaluate(BehavioralEvent ev, ProcessAncestry ancestry, BehavioralTimeline timeline)
    {
        if (ev.Kind != BehavioralEventKind.PersistenceCreated
            && ev.Kind != BehavioralEventKind.PersistenceModified)
            return Array.Empty<Evidence>();

        var recent = timeline.Around(ev.TimestampUtc, Window);
        BehavioralEvent? drop = null;
        foreach (var prior in recent)
        {
            if (prior.Kind != BehavioralEventKind.FileDropped) continue;
            if (prior.TimestampUtc > ev.TimestampUtc) continue;
            if (prior.Pid == ev.Pid || ShareTree(prior.Pid, ev.Pid, ancestry))
            {
                drop = prior;
                break;
            }
        }

        if (drop is null) return Array.Empty<Evidence>();

        int score = 8;
        return new[]
        {
            new Evidence
            {
                Category = "Behavioral",
                Description = $"Persistência ({ev.TargetPath}) criada {Math.Max(1, (int)(ev.TimestampUtc - drop.TimestampUtc).TotalSeconds)}s após drop de {drop.TargetPath}",
                ScoreDelta = score,
                Strength = EvidenceStrength.High,
                CanConfirmMalware = false,
            }
        };
    }

    private static bool ShareTree(int a, int b, ProcessAncestry ancestry)
    {
        var setA = new HashSet<int>(ancestry.Ancestors(a).Select(r => r.Pid));
        foreach (var ancestor in ancestry.Ancestors(b))
            if (setA.Contains(ancestor.Pid)) return true;
        return false;
    }
}
