using System;
using System.Collections.Generic;

namespace DataVanger.Shared.Behavioral.Runtime;

/// <summary>
/// Normalized, enriched behavioral observation derived from a single
/// <see cref="DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent"/> by
/// the <c>BehavioralRuntimeEventAdapter</c>.
///
/// An observation is a translation/enrichment of telemetry. It performs
/// NO classification: it does not decide malware, it does not quarantine,
/// it does not kill processes. The conservative rule evaluator consumes
/// observations (plus short-lived correlation state) to emit
/// <see cref="BehavioralRuntimeEvidence"/> — which is itself evidence
/// only.
/// </summary>
public sealed class BehavioralRuntimeObservation
{
    private static readonly IReadOnlyList<string> EmptyIndicators = Array.Empty<string>();

    public BehavioralObservationKind Kind { get; init; } = BehavioralObservationKind.Unknown;

    public DateTimeOffset TimestampUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Identifier of the source runtime event (for traceability).</summary>
    public string? SourceEventId { get; init; }

    public int? ProcessId { get; init; }
    public string? ProcessName { get; init; }
    public string? ImagePath { get; init; }
    public string? CommandLine { get; init; }

    public int? ParentProcessId { get; init; }

    /// <summary>
    /// Parent process name. May be supplied directly by the event or
    /// resolved from short-lived correlation state by parent PID.
    /// </summary>
    public string? ParentProcessName { get; init; }

    public string? ParentImagePath { get; init; }

    /// <summary>Subject path for file/persistence/tamper observations.</summary>
    public string? SubjectPath { get; init; }

    /// <summary>
    /// Conservative indicator tags (e.g. <c>powershell-encoded-command</c>).
    /// Descriptive only — indicators are NEVER verdicts.
    /// </summary>
    public IReadOnlyList<string> Indicators { get; init; } = EmptyIndicators;
}
