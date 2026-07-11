using System;

namespace DataVanger.Reporting.Forensics;

/// <summary>
/// One step inside an <see cref="EvidenceChain"/>.
///
/// A node is a thin, immutable wrapper around an existing
/// <see cref="DataVanger.Core.Evidence"/> (or around a synthesised
/// "anti-FP mitigation" note) plus enough metadata for the report layer
/// to render an ordered, sourced timeline of why a finding looks the way
/// it does.
///
/// Anti-FP invariant: <see cref="CanConfirmMalware"/> is preserved from
/// the source evidence. The chain builder never upgrades a heuristic-only
/// node into a confirmation; only confirmed evidence sources flip that
/// flag.
/// </summary>
public sealed class EvidenceChainNode
{
    public EvidenceChainNode(
        string sourceModule,
        string category,
        string description,
        int scoreDelta,
        DataVanger.Core.EvidenceStrength strength,
        bool canConfirmMalware,
        DateTime timestampUtc,
        string correlationId = "",
        string mitigationNote = "")
    {
        SourceModule = sourceModule ?? "";
        Category = category ?? "";
        Description = description ?? "";
        ScoreDelta = scoreDelta;
        Strength = strength;
        CanConfirmMalware = canConfirmMalware;
        TimestampUtc = timestampUtc == default
            ? DateTime.UtcNow
            : timestampUtc.ToUniversalTime();
        CorrelationId = correlationId ?? "";
        MitigationNote = mitigationNote ?? "";
    }

    /// <summary>Module that produced the evidence (e.g. "BehavioralEngine").</summary>
    public string SourceModule { get; }
    public string Category { get; }
    public string Description { get; }
    public int ScoreDelta { get; }
    public DataVanger.Core.EvidenceStrength Strength { get; }
    public bool CanConfirmMalware { get; }
    public DateTime TimestampUtc { get; }
    public string CorrelationId { get; }

    /// <summary>
    /// Non-empty when this node represents a deliberate severity reduction
    /// (e.g. "valid Chromium extension context"). Used by the false-positive
    /// transparency section of forensic reports.
    /// </summary>
    public string MitigationNote { get; }

    public bool IsMitigation => !string.IsNullOrEmpty(MitigationNote);

    public override string ToString()
    {
        string scoreSuffix = ScoreDelta == 0 ? "" : $" ({ScoreDelta:+#;-#;0})";
        string prefix = string.IsNullOrEmpty(SourceModule) ? "" : $"[{SourceModule}] ";
        return $"{prefix}{Category}: {Description}{scoreSuffix}";
    }
}
