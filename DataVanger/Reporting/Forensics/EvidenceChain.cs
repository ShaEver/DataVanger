using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.Reporting.Forensics;

/// <summary>
/// Ordered, sourced explanation of why a given finding looks the way it
/// does. A chain is the report-layer counterpart to the raw
/// <see cref="DataVanger.Core.Evidence"/> list: it preserves provenance
/// (which module produced what), the timeline (when the evidence was
/// observed) and any deliberate mitigations applied by the anti-FP
/// policy.
///
/// Anti-FP guarantee: <see cref="HasConfirmedEvidence"/> is true only
/// when at least one node is itself a confirmation. The chain never
/// invents confirmation by combining heuristic nodes.
/// </summary>
public sealed class EvidenceChain
{
    private readonly List<EvidenceChainNode> _nodes;

    public EvidenceChain(string targetId, string subject, IEnumerable<EvidenceChainNode>? nodes = null)
    {
        TargetId = targetId ?? "";
        Subject = subject ?? "";
        _nodes = nodes is null
            ? new List<EvidenceChainNode>()
            : nodes.Where(n => n != null).ToList();
    }

    /// <summary>Stable identifier of the entity the chain explains (path, pid, extension id).</summary>
    public string TargetId { get; }

    /// <summary>Human-readable subject line ("svchost.exe", "Chrome extension X").</summary>
    public string Subject { get; }

    public IReadOnlyList<EvidenceChainNode> Nodes => _nodes;

    public bool HasConfirmedEvidence => _nodes.Any(n => n.CanConfirmMalware
        || n.Strength == DataVanger.Core.EvidenceStrength.Confirmed);

    public IEnumerable<EvidenceChainNode> Escalations =>
        _nodes.Where(n => !n.IsMitigation && n.ScoreDelta > 0);

    public IEnumerable<EvidenceChainNode> Mitigations =>
        _nodes.Where(n => n.IsMitigation || n.ScoreDelta < 0);

    public int TotalScoreDelta => _nodes.Sum(n => n.ScoreDelta);

    public IReadOnlyList<string> ContributingModules =>
        _nodes.Select(n => n.SourceModule)
              .Where(m => !string.IsNullOrEmpty(m))
              .Distinct(StringComparer.OrdinalIgnoreCase)
              .ToList();

    public EvidenceChain Append(EvidenceChainNode node)
    {
        if (node != null) _nodes.Add(node);
        return this;
    }

    /// <summary>
    /// Builds a stable, deterministic textual summary of why severity was
    /// escalated. Order: highest strength first, ties broken by score
    /// delta then timestamp. Mitigations are omitted (they have their own
    /// rendering path).
    /// </summary>
    public string EscalationSummary()
    {
        var ordered = Escalations
            .OrderByDescending(n => (int)n.Strength)
            .ThenByDescending(n => n.ScoreDelta)
            .ThenBy(n => n.TimestampUtc)
            .Select(n => $"- {n}");
        return string.Join(Environment.NewLine, ordered);
    }
}
