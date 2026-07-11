using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core;
using DataVanger.Core.Domain;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// Contract for any per-file analyzer that contributes evidence to a verdict.
///
/// Design rules for module authors:
///
///   1. A module MUST return <see cref="Evidence"/>, never a final verdict.
///   2. A module MUST be deterministic given the same target and context.
///   3. A module MUST NOT terminate the scan on its own failure — return an
///      empty result and let the orchestrator log the warning.
///   4. A module MAY set <see cref="Evidence.CanConfirmMalware"/> only for
///      cryptographically grounded signals (hash match, signed YARA rule).
///      Heuristics alone NEVER confirm malware (anti-false-positive policy).
///   5. A module SHOULD short-circuit cheaply via <see cref="Supports"/> when
///      its capabilities don't apply (e.g. PE module on .txt files).
/// </summary>
public interface IDetectionModule
{
    /// <summary>Stable identifier used in reports and telemetry.</summary>
    string Name { get; }

    /// <summary>Capability flags consumed by the orchestrator.</summary>
    DetectionModuleCapabilities Capabilities { get; }

    /// <summary>Cheap eligibility predicate; called before <see cref="AnalyzeAsync"/>.</summary>
    bool Supports(ScanTarget target, ScanContext context);

    /// <summary>
    /// Analyzes the target and returns evidence. Returning an empty list means
    /// the module ran successfully and found nothing.
    /// </summary>
    Task<IReadOnlyList<Evidence>> AnalyzeAsync(
        ScanTarget target,
        ScanContext context,
        CancellationToken cancellationToken);
}
