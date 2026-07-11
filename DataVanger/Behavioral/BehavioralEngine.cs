using System;
using System.Collections.Generic;
using System.Linq;
using DataVanger.Behavioral.Rules;
using DataVanger.Core;

namespace DataVanger.Behavioral;

/// <summary>
/// Top-level facade for the Behavioral Engine subsystem.
///
/// Wires together:
///   - the in-memory event bus,
///   - process ancestry tracking,
///   - the rolling timeline,
///   - the rule engine,
///   - the correlation engine.
///
/// The engine is opt-in: nothing runs unless callers create an instance
/// and start publishing events into the bus (typically via monitors).
/// It is safe to leave running long term — every component is bounded.
///
/// Anti-FP contract:
///   - all emitted evidence has <see cref="Evidence.CanConfirmMalware"/> = false,
///   - all evidence stays under <see cref="EvidenceStrength.Confirmed"/>,
///   - chain scores cap at <see cref="RiskThresholds.High"/>.
/// </summary>
public sealed class BehavioralEngine : IDisposable
{
    private readonly BehavioralEventBus _bus;
    private readonly ProcessAncestry _ancestry;
    private readonly BehavioralTimeline _timeline;
    private readonly BehavioralRuleEngine _rules;
    private readonly BehavioralCorrelationEngine _correlation;
    private readonly IDisposable _subscription;
    private readonly Action<string>? _diagnostics;

    public IBehavioralEventBus Bus => _bus;
    public ProcessAncestry Ancestry => _ancestry;
    public BehavioralTimeline Timeline => _timeline;
    public BehavioralRuleEngine Rules => _rules;
    public BehavioralCorrelationEngine Correlation => _correlation;

    public BehavioralEngine(BehavioralEngineOptions? options = null)
    {
        options ??= new BehavioralEngineOptions();
        _diagnostics = options.Diagnostics;
        _bus = new BehavioralEventBus(options.BusCapacity, options.Diagnostics);
        _ancestry = new ProcessAncestry(options.MaxRetainedEndedProcesses);
        _timeline = new BehavioralTimeline(options.TimelineCapacity, options.TimelineRetention);
        _rules = new BehavioralRuleEngine(options.Rules ?? DefaultRules(), options.Diagnostics);
        _correlation = new BehavioralCorrelationEngine();
        _subscription = _bus.Subscribe(OnEvent);
    }

    public static IEnumerable<IBehavioralRule> DefaultRules()
    {
        yield return new EncodedPowerShellRule();
        yield return new LolbinAbuseRule();
        yield return new OfficeSpawnsScriptRule();
        yield return new SecurityTamperRule();
        yield return new PersistenceAfterDropRule();
    }

    /// <summary>
    /// Pull behavioral evidence relevant to <paramref name="finding"/> from the
    /// correlation engine. Looks up the running process matching the file path
    /// (if any) and surfaces the corresponding chain's evidence.
    ///
    /// Returns an empty list when nothing is known — never throws, never adds
    /// confirmed-malware evidence.
    /// </summary>
    public IReadOnlyList<Evidence> CollectEvidenceFor(ScanFinding finding)
    {
        if (finding is null || string.IsNullOrWhiteSpace(finding.Path)) return Array.Empty<Evidence>();
        var pid = FindPidByImagePath(finding.Path);
        if (pid <= 0) return Array.Empty<Evidence>();

        var chain = _correlation.GetChainForPid(pid, _ancestry);
        if (chain is null || !chain.HasAnyEvidence) return Array.Empty<Evidence>();

        // Make a defensive copy so callers can't mutate the chain's internal list.
        return chain.Evidence.Select(SanitizeForFinding).ToArray();
    }

    /// <summary>
    /// Apply behavioral evidence (if any) to a <see cref="ScanFinding"/>. Re-scores
    /// the finding by summing the new evidence's <see cref="Evidence.ScoreDelta"/>
    /// into <see cref="ScanFinding.Score"/>. Never escalates to ConfirmedMalware.
    /// </summary>
    public int Apply(ScanFinding finding)
    {
        var newEvidence = CollectEvidenceFor(finding);
        if (newEvidence.Count == 0) return 0;
        int added = 0;
        foreach (var e in newEvidence)
        {
            finding.Evidence.Add(e);
            added += e.ScoreDelta;
        }
        finding.Score = AntiFalsePositivePolicy_ClampedScore(finding, finding.Score + added);
        return added;
    }

    private static int AntiFalsePositivePolicy_ClampedScore(ScanFinding finding, int newScore)
    {
        return DataVanger.Classification.AntiFalsePositivePolicy
            .ClampToHighRiskWhenUnconfirmed(newScore, finding, finding.Evidence);
    }

    private static Evidence SanitizeForFinding(Evidence e) => new Evidence
    {
        Category = e.Category,
        Description = e.Description,
        ScoreDelta = e.ScoreDelta,
        Strength = e.Strength == EvidenceStrength.Confirmed ? EvidenceStrength.High : e.Strength,
        CanConfirmMalware = false,
    };

    private int FindPidByImagePath(string path)
    {
        string target = path.Trim();
        if (string.IsNullOrEmpty(target)) return 0;
        // Live first, then recently-ended.
        foreach (var rec in EnumerateAllRecords())
        {
            if (string.Equals(rec.ImagePath, target, StringComparison.OrdinalIgnoreCase))
                return rec.Pid;
        }
        return 0;
    }

    private IEnumerable<ProcessRecord> EnumerateAllRecords()
    {
        // We don't expose the dictionaries so we walk Ancestors of every pid we know about.
        // For test/use sizes (live + ended < ~1024) this is fine.
        var seen = new HashSet<int>();
        foreach (var chain in _correlation.Snapshot())
        {
            foreach (var pid in chain.Pids)
            {
                if (!seen.Add(pid)) continue;
                if (_ancestry.TryGet(pid, out var rec)) yield return rec;
            }
        }
    }

    private void OnEvent(BehavioralEvent ev)
    {
        try
        {
            UpdateAncestry(ev);
            _timeline.Record(ev);
            var evidence = _rules.Evaluate(ev, _ancestry, _timeline);
            if (evidence.Count > 0)
                _correlation.Record(ev, evidence, _ancestry);
        }
        catch (Exception ex)
        {
            try { _diagnostics?.Invoke($"behavioral engine error: {ex.GetType().Name}: {ex.Message}"); } catch (Exception) { /* Diagnostics sink must never throw back to callers - swallow intentionally. */ }
        }
    }

    private void UpdateAncestry(BehavioralEvent ev)
    {
        switch (ev.Kind)
        {
            case BehavioralEventKind.ProcessStart:
                _ancestry.Track(ev.Pid, ev.ParentPid, ev.ProcessName, ev.ImagePath, ev.CommandLine, ev.TimestampUtc);
                break;
            case BehavioralEventKind.ProcessEnd:
                _ancestry.MarkEnded(ev.Pid, ev.TimestampUtc);
                break;
            default:
                // Backfill ancestry on first sight if the process was missed.
                _ancestry.Track(ev.Pid, ev.ParentPid, ev.ProcessName, ev.ImagePath, ev.CommandLine, ev.TimestampUtc);
                break;
        }
    }

    /// <summary>Synchronously drain the bus — useful for tests and graceful shutdown.</summary>
    public int DrainNow() => _bus.DrainNow();

    public void Dispose()
    {
        try { _subscription.Dispose(); } catch (Exception) { /* Dispose may throw on already-disposed or never-started instances - ignore. */ }
        try { _bus.Dispose(); } catch (Exception) { /* Dispose may throw on already-disposed or never-started instances - ignore. */ }
    }
}

public sealed class BehavioralEngineOptions
{
    public int BusCapacity { get; init; } = 4096;
    public int TimelineCapacity { get; init; } = 4096;
    public TimeSpan TimelineRetention { get; init; } = TimeSpan.FromMinutes(5);
    public int MaxRetainedEndedProcesses { get; init; } = 512;
    public IEnumerable<IBehavioralRule>? Rules { get; init; }
    public Action<string>? Diagnostics { get; init; }
}
