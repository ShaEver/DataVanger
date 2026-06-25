using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;
using DataVanger.Engine.DeepScan;

namespace DataVanger.Engine.DeepScan.Stages;

/// <summary>
/// Local-database reputation lookup. Modeled after the legacy
/// <c>HashDetectionModule</c> but kept inside the deep pipeline so the rest
/// of the stages (correlation, classification) can short-circuit on a
/// confirmed verdict without re-running the detection chain.
/// </summary>
public sealed class ReputationStage : IPipelineStage
{
    private readonly ISignatureService _signatures;

    public ReputationStage(ISignatureService signatures) { _signatures = signatures; }

    public string Name => "Reputation";

    public Task<StageResult> ExecuteAsync(ScanWorkItem item, DeepScanContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        context.Telemetry.IncReputation();

        if (string.IsNullOrEmpty(item.Sha256)) return Task.FromResult(StageResult.Continue);

        if (_signatures.IsKnownMalicious(item.Sha256))
        {
            item.KnownMalicious = true;
            if (item.Target != null)
            {
                item.Target.IsKnownMalicious = true;
                item.Target.TrustState = FileTrustState.KnownMalicious;
                item.Target.Sha256 = item.Sha256;
            }
            item.AddEvidence(new Evidence
            {
                Category = "Reputation",
                Description = $"Hash conhecido como malicioso ({Truncate(item.Sha256)})",
                ScoreDelta = 100,
                Strength = EvidenceStrength.Confirmed,
                CanConfirmMalware = true,
            });
            return Task.FromResult(StageResult.Continue);
        }

        if (_signatures.IsKnownSafe(item.Sha256))
        {
            item.KnownSafe = true;
            if (item.Target != null) item.Target.TrustState = FileTrustState.KnownSafe;
        }
        return Task.FromResult(StageResult.Continue);
    }

    private static string Truncate(string hash) => hash.Length <= 12 ? hash : hash[..12] + "…";
}
