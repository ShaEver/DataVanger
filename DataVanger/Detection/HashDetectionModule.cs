using System;
using System.Collections.Generic;
using System.Threading;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;

namespace DataVanger.Detection;

/// <summary>
/// Looks the precomputed SHA-256 up in the local signature database.
///
/// This module is the canonical source of <see cref="Evidence.CanConfirmMalware"/>
/// — a hash match is the only signal cheap enough to authorize automatic
/// quarantine. The engine still cross-checks via
/// <see cref="Classification.AntiFalsePositivePolicy"/> before acting.
/// </summary>
public sealed class HashDetectionModule : DetectionModuleBase
{
    private readonly ISignatureService _signatures;

    public HashDetectionModule(ISignatureService signatures) { _signatures = signatures; }

    public override string Name => "HashLookup";
    public override DetectionModuleCapabilities Capabilities =>
        DetectionModuleCapabilities.NeedsHash | DetectionModuleCapabilities.CanConfirmMalware;

    public override bool Supports(ScanTarget target, ScanContext context) =>
        !string.IsNullOrWhiteSpace(target.Sha256);

    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(target.Sha256)) return Array.Empty<Evidence>();

        if (_signatures.IsKnownMalicious(target.Sha256))
        {
            target.IsKnownMalicious = true;
            target.TrustState = FileTrustState.KnownMalicious;
            return new[]
            {
                new Evidence
                {
                    Category = "Reputation",
                    Description = "Hash encontrado na base de malware conhecido",
                    Strength = EvidenceStrength.Confirmed,
                    CanConfirmMalware = true,
                    ScoreDelta = RiskThresholds.Critical + 10,
                }
            };
        }

        if (_signatures.IsKnownSafe(target.Sha256))
        {
            target.TrustState = FileTrustState.KnownSafe;
        }

        return Array.Empty<Evidence>();
    }
}
