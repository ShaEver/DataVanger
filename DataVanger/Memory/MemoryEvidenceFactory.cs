using System;
using System.Collections.Generic;
using DataVanger.Core;

namespace DataVanger.Memory;

/// <summary>
/// Translates a <see cref="MemoryFinding"/> into one or more
/// <see cref="Evidence"/> records that the existing scoring/
/// classification pipeline already understands.
///
/// Anti-FP invariants enforced here (single source of truth):
/// <list type="bullet">
///   <item>Strength is at most <see cref="EvidenceStrength.High"/>.</item>
///   <item><see cref="Evidence.CanConfirmMalware"/> is always false.</item>
///   <item>ScoreDelta is clamped to a sane positive range.</item>
/// </list>
/// </summary>
public static class MemoryEvidenceFactory
{
    public const string Category = "Memory";

    public static Evidence FromFinding(MemoryFinding finding)
    {
        if (finding is null) throw new ArgumentNullException(nameof(finding));

        var strength = finding.Severity switch
        {
            MemoryScanSeverity.High => EvidenceStrength.High,
            MemoryScanSeverity.Medium => EvidenceStrength.Medium,
            MemoryScanSeverity.Low => EvidenceStrength.Low,
            _ => EvidenceStrength.Info,
        };

        int score = finding.ScoreDelta;
        if (score < 0) score = 0;
        if (score > 6) score = 6; // hard ceiling: memory heuristics never push past the High band alone

        return new Evidence
        {
            Category = Category,
            Description = finding.Description,
            ScoreDelta = score,
            Strength = strength,
            CanConfirmMalware = false,
        };
    }

    public static IReadOnlyList<Evidence> FromFindings(IEnumerable<MemoryFinding> findings)
    {
        var list = new List<Evidence>();
        if (findings is null) return list;
        foreach (var f in findings)
        {
            if (f is null) continue;
            list.Add(FromFinding(f));
        }
        return list;
    }
}
