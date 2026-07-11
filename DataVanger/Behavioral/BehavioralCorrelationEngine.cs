using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using DataVanger.Core;

namespace DataVanger.Behavioral;

/// <summary>
/// Aggregates rule-produced evidence into per-process-tree correlation
/// chains.
///
/// A "chain" is the accumulated evidence the engine has seen for a
/// root process and all of its descendants, within the timeline's
/// retention window. Chains have a bounded score (clamped below
/// <see cref="RiskThresholds.Critical"/> to honour the project's
/// anti-FP contract: behavioral evidence is always heuristic).
/// </summary>
public sealed class BehavioralCorrelationEngine
{
    private readonly ConcurrentDictionary<int, BehavioralChain> _chains = new();
    private readonly object _sync = new();

    public int ChainCount => _chains.Count;

    public BehavioralChain Record(BehavioralEvent ev, IReadOnlyList<Evidence> evidence, ProcessAncestry ancestry)
    {
        int rootPid = ResolveTreeRoot(ev.Pid, ancestry);
        var chain = _chains.GetOrAdd(rootPid, pid => new BehavioralChain(pid));
        lock (_sync)
        {
            chain.Touch(ev.TimestampUtc);
            chain.AddPid(ev.Pid);
            foreach (var e in evidence)
            {
                chain.AddEvidence(e);
            }
        }
        return chain;
    }

    public BehavioralChain? GetChainForTreeRoot(int rootPid) =>
        _chains.TryGetValue(rootPid, out var c) ? c : null;

    public IReadOnlyCollection<BehavioralChain> Snapshot() => _chains.Values.ToArray();

    /// <summary>Returns the chain that contains <paramref name="pid"/> (looking up its tree root via ancestry).</summary>
    public BehavioralChain? GetChainForPid(int pid, ProcessAncestry ancestry)
    {
        int root = ResolveTreeRoot(pid, ancestry);
        return GetChainForTreeRoot(root);
    }

    public void Prune(TimeSpan staleAfter)
    {
        var cutoff = DateTime.UtcNow - staleAfter;
        foreach (var kvp in _chains.ToArray())
        {
            if (kvp.Value.LastUpdatedUtc < cutoff)
                _chains.TryRemove(kvp.Key, out _);
        }
    }

    private static int ResolveTreeRoot(int pid, ProcessAncestry ancestry)
    {
        int root = pid;
        foreach (var ancestor in ancestry.Ancestors(pid, maxDepth: 16))
        {
            root = ancestor.Pid;
        }
        return root;
    }
}

public sealed class BehavioralChain
{
    private readonly List<Evidence> _evidence = new();
    private readonly HashSet<int> _pids = new();

    public BehavioralChain(int rootPid)
    {
        RootPid = rootPid;
        StartedUtc = DateTime.UtcNow;
        LastUpdatedUtc = StartedUtc;
    }

    public int RootPid { get; }
    public DateTime StartedUtc { get; }
    public DateTime LastUpdatedUtc { get; private set; }
    public IReadOnlyList<Evidence> Evidence => _evidence;
    public IReadOnlyCollection<int> Pids => _pids;

    /// <summary>
    /// Total chain score. Clamped to <see cref="RiskThresholds.High"/>
    /// because behavioral evidence is heuristic by contract — it never
    /// reaches the <see cref="RiskThresholds.Critical"/> band on its
    /// own.
    /// </summary>
    public int Score
    {
        get
        {
            int raw = 0;
            foreach (var e in _evidence) raw += e.ScoreDelta;
            return raw >= RiskThresholds.High ? RiskThresholds.High : Math.Max(0, raw);
        }
    }

    public bool HasAnyEvidence => _evidence.Count > 0;

    internal void Touch(DateTime when) => LastUpdatedUtc = when == default ? DateTime.UtcNow : when.ToUniversalTime();
    internal void AddPid(int pid) => _pids.Add(pid);
    internal void AddEvidence(Evidence e)
    {
        // Defensive: never let confirmed evidence enter a behavioral chain.
        if (e.CanConfirmMalware || e.Strength == EvidenceStrength.Confirmed)
        {
            _evidence.Add(new Evidence
            {
                Category = e.Category,
                Description = e.Description,
                ScoreDelta = e.ScoreDelta,
                Strength = EvidenceStrength.High,
                CanConfirmMalware = false,
            });
        }
        else
        {
            _evidence.Add(e);
        }
    }
}
