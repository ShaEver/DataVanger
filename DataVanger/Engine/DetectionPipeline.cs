using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;
using DataVanger.Detection;

namespace DataVanger.Engine;

/// <summary>
/// Per-file detection pipeline.
///
/// One <see cref="DetectionPipeline"/> instance is constructed per scan and
/// reused across all worker tasks. It is thread-safe because every dependency
/// it holds is read-only.
///
/// Flow for a single target:
///
///   1. Run modules in registry order, accumulating evidence.
///   2. Stop early if a module marks the target as KnownSafe.
///   3. Aggregate ScoreDelta values into a preliminary score.
///   4. Hand the evidence list to the classifier — it owns the verdict.
///
/// The pipeline does NOT perform IO of its own (no hashing, no signature
/// lookup, no quarantine). Those concerns live in services injected upstream.
/// </summary>
public sealed class DetectionPipeline
{
    private readonly DetectionModuleRegistry _registry;
    private readonly IThreatClassifier _classifier;
    private readonly IScanLogger _logger;

    public DetectionPipeline(DetectionModuleRegistry registry, IThreatClassifier classifier, IScanLogger logger)
    {
        _registry = registry;
        _classifier = classifier;
        _logger = logger;
    }

    public sealed record ModuleResult(string ModuleName, IReadOnlyList<Evidence> Evidence);

    public async Task<PipelineOutcome> AnalyzeAsync(
        ScanTarget target,
        ScanContext context,
        CancellationToken cancellationToken,
        DetectionModuleSet? modulesToRun = null)
    {
        var evidence = new List<Evidence>();
        var moduleResults = new List<ModuleResult>(_registry.Modules.Count);
        bool anyConfirmed = false;

        foreach (var module in _registry.Modules)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // KnownSafe short-circuit: once the hash module marks a target as
            // KnownSafe we still let modules with CanConfirmMalware (e.g. a
            // future cloud reputation hit) run, so a poisoned local whitelist
            // can never permanently suppress a true positive. Heuristic-only
            // modules are skipped to save CPU.
            if (target.TrustState == FileTrustState.KnownSafe
                && (module.Capabilities & DetectionModuleCapabilities.CanConfirmMalware) == 0)
                continue;

            if (!module.Supports(target, context)) continue;

            if (modulesToRun != null && !modulesToRun.IsEnabled(module.Name)) continue;

            IReadOnlyList<Evidence> moduleEvidence;
            try
            {
                moduleEvidence = await module.AnalyzeAsync(target, context, cancellationToken).ConfigureAwait(false);
            }
            catch (System.OperationCanceledException) { throw; }
            catch (System.Exception ex)
            {
                _logger.ModuleFailure(module.Name, target.FullPath, ex);
                continue;
            }

            if (moduleEvidence.Count == 0) continue;

            evidence.AddRange(moduleEvidence);
            moduleResults.Add(new ModuleResult(module.Name, moduleEvidence));

            if (!anyConfirmed)
            {
                foreach (var ev in moduleEvidence)
                {
                    if (ev.CanConfirmMalware || ev.Strength == EvidenceStrength.Confirmed)
                    {
                        anyConfirmed = true;
                        break;
                    }
                }
            }
        }

        int score = evidence.Sum(e => e.ScoreDelta);
        return new PipelineOutcome(evidence, moduleResults, score, anyConfirmed);
    }
}

/// <summary>
/// Result of one pipeline invocation. The engine uses this to fill the
/// final <see cref="ScanFinding"/> and to feed the classifier.
/// </summary>
public sealed record PipelineOutcome(
    List<Evidence> Evidence,
    List<DetectionPipeline.ModuleResult> Modules,
    int AggregatedScore,
    bool AnyConfirmedEvidence);
