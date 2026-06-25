using System;
using System.Collections.Generic;
using DataVanger.Behavioral;
using DataVanger.Core;

namespace DataVanger.Memory;

/// <summary>
/// Correlates memory findings with already-collected behavioral /
/// runtime evidence. Lives next to the Memory scanner so the behavioral
/// engine itself doesn't have to know about memory regions.
/// </summary>
public sealed class MemoryCorrelationEngine
{
    /// <summary>
    /// Build a flat list of <see cref="Evidence"/> for one process from
    /// its memory findings, optionally upgrading the description when
    /// behavioral events for the same PID already exist (e.g. an
    /// InjectionIndicator behavioral event combined with a
    /// ReflectivePeIndicator memory finding both point at PID X).
    ///
    /// Anti-FP invariant: the returned evidence always has
    /// CanConfirmMalware=false and Strength &lt;= High, regardless of
    /// how many indicators line up.
    /// </summary>
    public IReadOnlyList<Evidence> CorrelateForProcess(
        int processId,
        IReadOnlyList<MemoryFinding> memoryFindings,
        IReadOnlyList<BehavioralEvent>? recentBehavioralEvents = null)
    {
        var result = new List<Evidence>();
        if (memoryFindings is null) return result;

        bool hasInjectionEvent = false;
        bool hasAmsiBypassEvent = false;
        if (recentBehavioralEvents is not null)
        {
            foreach (var ev in recentBehavioralEvents)
            {
                if (ev is null) continue;
                if (ev.Pid != processId) continue;
                if (ev.Kind == BehavioralEventKind.InjectionIndicator) hasInjectionEvent = true;
                if (ev.Kind == BehavioralEventKind.AmsiBypassIndicator) hasAmsiBypassEvent = true;
            }
        }

        foreach (var f in memoryFindings)
        {
            if (f is null) continue;
            if (f.ProcessId != processId) continue;
            var ev = MemoryEvidenceFactory.FromFinding(f);

            if (hasInjectionEvent && IsInjectionFlavored(f.Kind))
                ev = AnnotateCorrelated(ev, "evento de injeção comportamental no mesmo PID");
            else if (hasAmsiBypassEvent && IsScriptFlavored(f.Kind))
                ev = AnnotateCorrelated(ev, "telemetria AMSI de bypass no mesmo PID");

            result.Add(ev);
        }
        return result;
    }

    /// <summary>
    /// Convenience: apply memory findings (with optional correlation)
    /// directly to a <see cref="ScanFinding"/>, going through the
    /// existing AntiFalsePositivePolicy clamp so the score is bounded
    /// to HighRisk when nothing confirmable backs it up.
    /// </summary>
    public int Apply(
        ScanFinding finding,
        int processId,
        IReadOnlyList<MemoryFinding> memoryFindings,
        IReadOnlyList<BehavioralEvent>? recentBehavioralEvents = null)
    {
        if (finding is null) throw new ArgumentNullException(nameof(finding));
        var evidence = CorrelateForProcess(processId, memoryFindings, recentBehavioralEvents);
        int added = 0;
        foreach (var e in evidence)
        {
            finding.Evidence.Add(e);
            added += e.ScoreDelta;
        }
        if (added > 0)
        {
            finding.Score = DataVanger.Classification.AntiFalsePositivePolicy
                .ClampToHighRiskWhenUnconfirmed(finding.Score + added, finding, finding.Evidence);
        }
        return added;
    }

    private static bool IsInjectionFlavored(MemoryFindingKind k) =>
        k == MemoryFindingKind.RwxPrivateRegion
        || k == MemoryFindingKind.AnonymousExecutableRegion
        || k == MemoryFindingKind.ReflectivePeIndicator
        || k == MemoryFindingKind.HollowingIndicator
        || k == MemoryFindingKind.ShellcodeLikePattern;

    private static bool IsScriptFlavored(MemoryFindingKind k) =>
        k == MemoryFindingKind.HighEntropyExecutable
        || k == MemoryFindingKind.ReflectivePeIndicator;

    private static Evidence AnnotateCorrelated(Evidence original, string note)
    {
        return new Evidence
        {
            Category = original.Category,
            Description = original.Description + $" [correlação: {note}]",
            ScoreDelta = Math.Min(original.ScoreDelta + 1, 6),
            Strength = original.Strength == EvidenceStrength.Low ? EvidenceStrength.Medium : original.Strength,
            CanConfirmMalware = false,
        };
    }
}
