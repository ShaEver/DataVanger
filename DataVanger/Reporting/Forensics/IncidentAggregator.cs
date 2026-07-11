using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.Reporting.Forensics;

/// <summary>
/// Groups <see cref="EvidenceChain"/> instances into
/// <see cref="Incident"/>s.
///
/// Grouping is intentionally conservative: chains are merged only when
/// they share an explicit correlation key (a non-empty
/// <see cref="EvidenceChainNode.CorrelationId"/>) or when they were
/// produced for the exact same <see cref="EvidenceChain.TargetId"/>. We
/// deliberately do NOT use heuristic proximity (filename similarity,
/// folder co-location) — that would risk merging unrelated findings into
/// the same incident, which inflates user-visible severity and would
/// erode trust.
///
/// Anti-FP guarantee:
///   - Severity of the aggregated incident is the maximum severity of
///     its contributing chains, capped at
///     <see cref="ForensicSeverity.Critical"/> unless at least one chain
///     has confirmed evidence. Heuristic-only chains cannot become a
///     <see cref="ForensicSeverity.ConfirmedMalware"/> incident no matter
///     how many of them are correlated.
///   - All mitigation notes from the contributing chains are propagated
///     to <see cref="Incident.MitigationNotes"/> so the report layer can
///     surface them transparently.
/// </summary>
public sealed class IncidentAggregator
{
    /// <summary>
    /// Defensive ceiling on the number of distinct incident buckets we will
    /// materialize from a single aggregation pass. A pathological scan that
    /// produces millions of unrelated chains (one per file in a corrupted
    /// archive, say) should not be allowed to balloon the report into an
    /// unrenderable size. Excess chains continue to land in the most-recent
    /// bucket so no signal is silently lost — only further bucket creation
    /// is suppressed.
    /// </summary>
    public const int MaxIncidentBuckets = 50_000;

    /// <summary>
    /// Builds the incident list from a flat sequence of chains. The order
    /// of the resulting list is deterministic: incidents are sorted by
    /// severity desc, then by confidence desc, then by id asc.
    /// </summary>
    public IReadOnlyList<Incident> Aggregate(
        IEnumerable<EvidenceChain> chains,
        IReadOnlyDictionary<string, ForensicSeverity>? chainSeverity = null,
        IReadOnlyDictionary<string, ForensicConfidence>? chainConfidence = null,
        ForensicTimeline? timeline = null)
    {
        if (chains == null) return System.Array.Empty<Incident>();
        chainSeverity ??= new Dictionary<string, ForensicSeverity>();
        chainConfidence ??= new Dictionary<string, ForensicConfidence>();

        var buckets = new Dictionary<string, List<EvidenceChain>>(StringComparer.OrdinalIgnoreCase);
        string? overflowKey = null;

        foreach (var chain in chains.Where(c => c != null))
        {
            string key = ResolveCorrelationKey(chain);
            if (!buckets.TryGetValue(key, out var bucket))
            {
                if (buckets.Count >= MaxIncidentBuckets)
                {
                    // Cap reached: funnel further chains into an overflow bucket
                    // so we never lose evidence but also never grow without bound.
                    overflowKey ??= "overflow:incidents-cap-reached";
                    if (!buckets.TryGetValue(overflowKey, out var ov))
                    {
                        ov = new List<EvidenceChain>();
                        buckets[overflowKey] = ov;
                    }
                    ov.Add(chain);
                    continue;
                }
                bucket = new List<EvidenceChain>();
                buckets[key] = bucket;
            }
            bucket.Add(chain);
        }

        var incidents = new List<Incident>(buckets.Count);
        foreach (var bucket in buckets.Values)
        {
            incidents.Add(BuildIncident(bucket, chainSeverity, chainConfidence, timeline));
        }

        return incidents
            .OrderByDescending(i => (int)i.Severity)
            .ThenByDescending(i => (int)i.Confidence)
            .ThenBy(i => i.Id, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string ResolveCorrelationKey(EvidenceChain chain)
    {
        var firstCorrelation = chain.Nodes
            .Select(n => n.CorrelationId)
            .FirstOrDefault(c => !string.IsNullOrEmpty(c));
        if (!string.IsNullOrEmpty(firstCorrelation))
        {
            return "corr:" + firstCorrelation;
        }
        return "target:" + (chain.TargetId ?? "");
    }

    private static Incident BuildIncident(
        IReadOnlyList<EvidenceChain> chains,
        IReadOnlyDictionary<string, ForensicSeverity> chainSeverity,
        IReadOnlyDictionary<string, ForensicConfidence> chainConfidence,
        ForensicTimeline? timeline)
    {
        bool anyConfirmed = chains.Any(c => c.HasConfirmedEvidence);

        var severities = chains.Select(c =>
            chainSeverity.TryGetValue(c.TargetId, out var s) ? s : ForensicSeverity.Informational);
        var maxSeverity = severities.DefaultIfEmpty(ForensicSeverity.Informational).Max();
        if (!anyConfirmed && maxSeverity == ForensicSeverity.ConfirmedMalware)
        {
            maxSeverity = ForensicSeverity.Critical;
        }

        var confidences = chains.Select(c =>
            chainConfidence.TryGetValue(c.TargetId, out var cf) ? cf : ForensicConfidence.Heuristic);
        var maxConfidence = confidences.DefaultIfEmpty(ForensicConfidence.Heuristic).Max();
        if (!anyConfirmed && maxConfidence == ForensicConfidence.Confirmed)
        {
            maxConfidence = ForensicConfidence.High;
        }

        var correlationIds = chains
            .SelectMany(c => c.Nodes)
            .Select(n => n.CorrelationId)
            .Where(id => !string.IsNullOrEmpty(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        IEnumerable<TimelineEvent> incidentTimeline = System.Array.Empty<TimelineEvent>();
        if (timeline != null && correlationIds.Count > 0)
        {
            var seen = new HashSet<TimelineEvent>();
            var collected = new List<TimelineEvent>();
            foreach (var corr in correlationIds)
            {
                foreach (var evt in timeline.ForCorrelation(corr))
                {
                    if (seen.Add(evt)) collected.Add(evt);
                }
            }
            incidentTimeline = collected;
        }

        string id = chains[0].TargetId;
        if (string.IsNullOrEmpty(id)) id = correlationIds.FirstOrDefault() ?? Guid.NewGuid().ToString("N");

        string title = chains
            .Select(c => c.Subject)
            .FirstOrDefault(s => !string.IsNullOrEmpty(s)) ?? id;

        var mitigations = chains.SelectMany(c => c.Mitigations.Select(m => m.MitigationNote));

        return new Incident(id, title, maxSeverity, maxConfidence, chains, incidentTimeline, mitigations);
    }
}
