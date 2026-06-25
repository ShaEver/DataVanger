using System;
using System.Collections.Generic;

namespace DataVanger.Shared.ProtectedFiles;

/// <summary>
/// Normalized, enriched file-activity observation derived from a single
/// <see cref="DataVanger.Shared.RuntimeEvents.RuntimeSecurityEvent"/> by
/// the <c>ProtectedFilesActivityEventAdapter</c>.
///
/// An observation is a translation/enrichment of telemetry. It performs
/// NO classification: it does not decide malware, it does not quarantine,
/// it does not kill processes, it does not block writes. The conservative
/// scoring policy consumes observations (plus short-lived, bounded
/// correlation state) to emit
/// <see cref="ProtectedFilesActivityEvidence"/> — which is itself
/// evidence only.
/// </summary>
public sealed class ProtectedFileObservation
{
    private static readonly IReadOnlyList<string> EmptyLabels = Array.Empty<string>();

    public ProtectedFileObservationKind Kind { get; init; } = ProtectedFileObservationKind.Unknown;

    public DateTimeOffset TimestampUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Identifier of the source runtime event (for traceability).</summary>
    public string? SourceEventId { get; init; }

    public int? ProcessId { get; init; }
    public string? ProcessName { get; init; }
    public string? ProcessImagePath { get; init; }
    public int? ParentProcessId { get; init; }
    public string? ParentProcessName { get; init; }

    /// <summary>Affected file/directory path (the subject of the activity).</summary>
    public string? SubjectPath { get; init; }

    /// <summary>
    /// For rename observations: the previous path before the rename, when
    /// the producer supplied it (metadata key
    /// <c>protectedfiles.previous_path</c>). Enables extension-transition
    /// analysis.
    /// </summary>
    public string? PreviousPath { get; init; }

    /// <summary>Optional reported byte count for the mutation (bounded, advisory only).</summary>
    public long? ByteCount { get; init; }

    /// <summary>
    /// Optional pre-computed entropy of the file AFTER the mutation, in
    /// bits/byte (0..8). Producers supply this only when entropy sampling
    /// is enabled and bounded. The monitor NEVER reads file contents
    /// itself.
    /// </summary>
    public double? EntropyAfter { get; init; }

    /// <summary>Optional pre-computed entropy BEFORE the mutation, in bits/byte (0..8).</summary>
    public double? EntropyBefore { get; init; }

    /// <summary>
    /// Normalized recovery-protection indicator labels carried by the
    /// event (labels ONLY — never reconstructed commands).
    /// </summary>
    public IReadOnlyList<string> RecoveryIndicators { get; init; } = EmptyLabels;
}
