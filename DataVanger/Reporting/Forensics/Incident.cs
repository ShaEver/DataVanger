using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.Reporting.Forensics;

/// <summary>
/// A correlated group of findings/events that the reporting layer is
/// confident represent a single behavioural story (e.g. "Office document
/// spawned PowerShell that dropped an executable").
///
/// An <see cref="Incident"/> is purely a presentation construct. It does
/// not authorise quarantine, does not change classifier verdicts and
/// does not turn heuristic-only evidence into confirmed malware. The
/// <see cref="Severity"/> is the maximum severity of the contributing
/// findings, capped at <see cref="ForensicSeverity.Critical"/> unless at
/// least one contributing finding is itself
/// <see cref="ForensicSeverity.ConfirmedMalware"/>.
/// </summary>
public sealed class Incident
{
    public Incident(
        string id,
        string title,
        ForensicSeverity severity,
        ForensicConfidence confidence,
        IEnumerable<EvidenceChain> chains,
        IEnumerable<TimelineEvent>? timeline = null,
        IEnumerable<string>? mitigationNotes = null)
    {
        Id = string.IsNullOrEmpty(id)
            ? Guid.NewGuid().ToString("N")
            : id;
        Title = title ?? "";
        Severity = severity;
        Confidence = confidence;
        Chains = chains?.Where(c => c != null).ToList()
            ?? new List<EvidenceChain>();
        Timeline = timeline?.OrderBy(e => e.TimestampUtc).ToList()
            ?? new List<TimelineEvent>();
        MitigationNotes = mitigationNotes?.Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList() ?? new List<string>();
    }

    public string Id { get; }
    public string Title { get; }
    public ForensicSeverity Severity { get; }
    public ForensicConfidence Confidence { get; }
    public IReadOnlyList<EvidenceChain> Chains { get; }
    public IReadOnlyList<TimelineEvent> Timeline { get; }
    public IReadOnlyList<string> MitigationNotes { get; }

    public bool IsConfirmed => Severity == ForensicSeverity.ConfirmedMalware
        && Chains.Any(c => c.HasConfirmedEvidence);

    /// <summary>
    /// True when at least one contributing chain carried an explicit
    /// mitigation, OR the incident itself was annotated with a
    /// false-positive note. Used by reports to flag "this could be a
    /// false positive" sections.
    /// </summary>
    public bool HasMitigations => MitigationNotes.Count > 0
        || Chains.Any(c => c.Mitigations.Any());

    public IReadOnlyList<string> ContributingModules => Chains
        .SelectMany(c => c.ContributingModules)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .OrderBy(m => m, StringComparer.OrdinalIgnoreCase)
        .ToList();
}
