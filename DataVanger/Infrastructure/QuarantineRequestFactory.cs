using System;
using System.Linq;
using DataVanger.Core;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Infrastructure;

/// <summary>Pure mapping from an already-classified finding into a V2 request.</summary>
public static class QuarantineRequestFactory
{
    public static QuarantineRequest Create(
        ScanFinding finding,
        QuarantineRequestOrigin origin,
        string sourceModule)
    {
        ArgumentNullException.ThrowIfNull(finding);
        return new QuarantineRequest
        {
            SourcePath = finding.Path,
            Origin = origin,
            Classification = Map(finding.Classification),
            RequestedAction = QuarantineRequestedAction.Quarantine,
            DetectionSummary = finding.Reasons,
            ActionReason = origin == QuarantineRequestOrigin.Automatic
                ? "Confirmed-malware automatic-action policy approved the request."
                : "The interactive user explicitly approved quarantine.",
            SourceModule = sourceModule,
            EvidenceIds = finding.Evidence
                .Select(e => $"{e.Category}:{e.Description}")
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.Ordinal)
                .ToList(),
            ExpectedSha256 = finding.SHA256,
            DeleteOriginalAfterStore = true,
        };
    }

    public static QuarantineThreatClassification Map(ThreatClass classification) => classification switch
    {
        ThreatClass.ConfirmedMalware => QuarantineThreatClassification.ConfirmedMalware,
        ThreatClass.HighRisk => QuarantineThreatClassification.HighRisk,
        ThreatClass.Suspect => QuarantineThreatClassification.Suspect,
        _ => QuarantineThreatClassification.Clean,
    };
}
