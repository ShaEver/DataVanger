using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;
using DataVanger.Engine.DeepScan.Stages;

namespace DataVanger.Engine.DeepScan;

/// <summary>
/// Glue between the high-level <see cref="DataVanger.Core.ScanEngine"/> and the
/// new <see cref="DeepScanOrchestrator"/>.
///
/// Callers (the WPF engine, the CLI, future tests) pass in the already-built
/// service graph; the runner only knows how to:
///   - resolve a <see cref="DeepScanProfileSettings"/>,
///   - construct the orchestrator with the default stage list,
///   - return the pipeline's raw result.
/// </summary>
public static class DeepScanRunner
{
    public static Task<DeepScanResult> RunAsync(
        IEnumerable<string> roots,
        ScanOptions options,
        AppSettings settings,
        DetectionModuleRegistry modules,
        DetectionPipeline detectionPipeline,
        ISignatureService signatures,
        IFileSystemService fileSystem,
        IScanLogger logger,
        ScanContext scanContext,
        CancellationToken cancellationToken,
        DeepScanTelemetry? telemetry = null)
    {
        var profile = DeepScanProfileSettings.Resolve(options.Profile, settings, options);
        var stages = DeepScanOrchestrator.BuildDefaultStages(signatures, detectionPipeline);
        var discovery = new DiscoveryStage(fileSystem);
        var orchestrator = new DeepScanOrchestrator(new DeepScanOrchestratorOptions
        {
            Profile = profile,
            Discovery = discovery,
            Stages = stages,
            Modules = modules,
            Logger = logger,
            Telemetry = telemetry,
        });
        return orchestrator.RunAsync(roots, scanContext, cancellationToken);
    }

    /// <summary>
    /// Convenience adapter that converts the pipeline's work items into
    /// legacy <see cref="ScanFinding"/> instances, so reports and quarantine
    /// flows can keep using their existing serialisers.
    /// </summary>
    public static List<ScanFinding> MapFindings(DeepScanResult result)
    {
        var findings = new List<ScanFinding>(result.Items.Length);
        foreach (var item in result.Items)
        {
            var f = new ScanFinding
            {
                Path = item.Source.LogicalPath,
                Extension = System.IO.Path.GetExtension(item.Source.LogicalPath).ToLowerInvariant(),
                SizeKB = item.Source.Length / 1024,
                SHA256 = item.Sha256,
                Score = item.Score,
                IsBlacklisted = item.KnownMalicious,
                HasConfirmedSignature = item.Evidence.Any(e => e.CanConfirmMalware),
                Reasons = item.Evidence.Count == 0
                    ? "Sem motivo específico"
                    : string.Join("; ", item.Evidence.Select(e => e.Description)),
                Evidence = item.Evidence.ToList(),
            };
            findings.Add(f);
        }
        return findings;
    }
}
