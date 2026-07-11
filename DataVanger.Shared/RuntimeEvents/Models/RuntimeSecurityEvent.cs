using System;
using System.Collections.Generic;

namespace DataVanger.Shared.RuntimeEvents;

/// <summary>
/// Centralized runtime security event used by every producer module
/// (real-time file protection, ETW telemetry, behavioral engine, anti-
/// ransomware, self-protection, reporting, scheduler, service host,
/// UI, test harness).
///
/// Anti-FP guarantee:
///   A RuntimeSecurityEvent is telemetry. It NEVER classifies a file
///   or process as ConfirmedMalware. The pipeline does not bypass the
///   existing classification policy. ConfirmedMalware MUST originate
///   from the scan engine + classification policy, not from runtime
///   telemetry severity.
/// </summary>
public sealed class RuntimeSecurityEvent
{
    private static readonly IReadOnlyDictionary<string, string> EmptyMetadata =
        new Dictionary<string, string>(0);

    private static readonly IReadOnlyList<RuntimeEvidenceReference> EmptyEvidence =
        Array.Empty<RuntimeEvidenceReference>();

    /// <summary>
    /// Stable identifier for this event. Defaults to a GUID; producers
    /// may supply a deterministic id for tests.
    /// </summary>
    public string EventId { get; init; } = Guid.NewGuid().ToString("N");

    public DateTimeOffset TimestampUtc { get; init; } = DateTimeOffset.UtcNow;

    public RuntimeEventSource Source { get; init; } = RuntimeEventSource.Unknown;

    public RuntimeEventCategory Category { get; init; } = RuntimeEventCategory.Unknown;

    public RuntimeEventSeverity Severity { get; init; } = RuntimeEventSeverity.Informational;

    public string Title { get; init; } = string.Empty;

    public string Description { get; init; } = string.Empty;

    /// <summary>
    /// Optional path of the subject (file, directory, registry key). May
    /// be null for non-file events.
    /// </summary>
    public string? SubjectPath { get; init; }

    public string? ProcessName { get; init; }
    public int? ProcessId { get; init; }
    public string? ParentProcessName { get; init; }
    public int? ParentProcessId { get; init; }
    public string? UserName { get; init; }

    /// <summary>
    /// Free-form metadata. Producers SHOULD keep values short — large
    /// binary payloads belong in evidence references, not metadata.
    /// </summary>
    public IReadOnlyDictionary<string, string> Metadata { get; init; } = EmptyMetadata;

    public IReadOnlyList<RuntimeEvidenceReference> Evidence { get; init; } = EmptyEvidence;
}
