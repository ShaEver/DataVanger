using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;

namespace DataVanger.Detection;

/// <summary>
/// Convenience base class for detection modules. Provides exception isolation
/// and a helper that converts an <see cref="AnalysisResult"/> from the legacy
/// static analyzers into the module's evidence list.
///
/// Subclasses implement <see cref="Supports"/> and the synchronous
/// <see cref="Analyze"/> hook; the base class wraps it in a Task and catches
/// any unexpected exception so a single bad file can never poison the scan.
/// </summary>
public abstract class DetectionModuleBase : IDetectionModule
{
    public abstract string Name { get; }
    public abstract DetectionModuleCapabilities Capabilities { get; }

    public abstract bool Supports(ScanTarget target, ScanContext context);

    public Task<IReadOnlyList<Evidence>> AnalyzeAsync(
        ScanTarget target,
        ScanContext context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            return Task.FromResult<IReadOnlyList<Evidence>>(Analyze(target, context, cancellationToken));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (System.Exception)
        {
            // Module resilience: a thrown exception in one module on one file
            // is recorded as zero evidence rather than as a scan-killing error.
            return Task.FromResult<IReadOnlyList<Evidence>>(Array.Empty<Evidence>());
        }
    }

    /// <summary>
    /// Synchronous analysis hook. Override this for CPU-bound modules
    /// (script regex, archive walk). Async modules can override
    /// <see cref="AnalyzeAsync"/> directly.
    /// </summary>
    protected virtual IReadOnlyList<Evidence> Analyze(
        ScanTarget target,
        ScanContext context,
        CancellationToken cancellationToken) => Array.Empty<Evidence>();

    /// <summary>Promotes an <see cref="AnalysisResult"/> from the legacy static analyzers.</summary>
    protected static IReadOnlyList<Evidence> FromAnalysisResult(AnalysisResult result) =>
        result.HasHits ? result.Evidence : Array.Empty<Evidence>();
}
