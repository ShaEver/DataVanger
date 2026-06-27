using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using DataVanger.Shared.Quarantine;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Engine.Quarantine;

/// <summary>No-op audit sink. Used when no telemetry destination is wired.</summary>
public sealed class NullQuarantineAuditSink : IQuarantineAuditSink
{
    public static readonly NullQuarantineAuditSink Instance = new();
    public void Publish(QuarantineAuditEvent auditEvent) { /* intentionally empty */ }
}

/// <summary>
/// Deterministic collecting sink for tests and one-process scenarios. Records
/// every audit event in publication order. Passive — never acts.
/// </summary>
public sealed class CollectingQuarantineAuditSink : IQuarantineAuditSink
{
    private readonly object _gate = new();
    private readonly List<QuarantineAuditEvent> _events = new();

    public int Count { get { lock (_gate) return _events.Count; } }

    public IReadOnlyList<QuarantineAuditEvent> Snapshot()
    {
        lock (_gate) return _events.ToArray();
    }

    public bool Any(QuarantineAuditEventKind kind)
    {
        lock (_gate) return _events.Any(e => e.Kind == kind);
    }

    public void Publish(QuarantineAuditEvent auditEvent)
    {
        if (auditEvent is null) return;
        lock (_gate) _events.Add(auditEvent);
    }
}

/// <summary>
/// Bridges quarantine audit events onto the runtime event pipeline as
/// telemetry. Every emitted <see cref="RuntimeSecurityEvent"/> uses
/// <see cref="RuntimeEventSource.Quarantine"/> and
/// <see cref="RuntimeEventCategory.QuarantineAction"/>, carries only
/// report-safe metadata (quarantine id, SHA-256, classification label, result,
/// state), and NEVER escalates into a malware verdict.
///
/// A failure publishing telemetry must never break a quarantine operation, so
/// publish failures are swallowed.
/// </summary>
public sealed class RuntimeEventQuarantineAuditSink : IQuarantineAuditSink
{
    private readonly IRuntimeEventPublisher _publisher;

    public RuntimeEventQuarantineAuditSink(IRuntimeEventPublisher publisher)
    {
        _publisher = publisher ?? throw new ArgumentNullException(nameof(publisher));
    }

    public void Publish(QuarantineAuditEvent auditEvent)
    {
        if (auditEvent is null) return;

        var metadata = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["kind"] = auditEvent.Kind.ToString(),
            ["resultStatus"] = auditEvent.ResultStatus.ToString(),
            ["classification"] = auditEvent.Classification.ToString(),
        };
        if (!string.IsNullOrEmpty(auditEvent.QuarantineId)) metadata["quarantineId"] = auditEvent.QuarantineId!;
        if (!string.IsNullOrEmpty(auditEvent.OriginalSha256)) metadata["originalSha256"] = auditEvent.OriginalSha256!;
        if (auditEvent.RecordState is { } st) metadata["recordState"] = st.ToString();
        metadata["timestampUtc"] = auditEvent.TimestampUtc.ToString("O", CultureInfo.InvariantCulture);

        var runtimeEvent = new RuntimeSecurityEvent
        {
            Source = RuntimeEventSource.Quarantine,
            Category = RuntimeEventCategory.QuarantineAction,
            Severity = MapSeverity(auditEvent.Kind),
            Title = auditEvent.Kind.ToString(),
            Description = auditEvent.Message,
            SubjectPath = null,   // never disclose original path in runtime telemetry
            Metadata = metadata,
        };

        try
        {
            // Fire the telemetry publish without blocking the quarantine path.
            // PublishAsync on the in-memory pipeline dispatches inline; we simply
            // do not await here and protect against any synchronous throw.
            _ = _publisher.PublishAsync(runtimeEvent, CancellationToken.None);
        }
        catch (System.Exception)
        {
            // Telemetry must never break a quarantine/restore operation.
        }
    }

    private static RuntimeEventSeverity MapSeverity(QuarantineAuditEventKind kind) => kind switch
    {
        QuarantineAuditEventKind.QuarantineIntegrityFailed => RuntimeEventSeverity.High,
        QuarantineAuditEventKind.QuarantineMetadataTamperDetected => RuntimeEventSeverity.High,
        QuarantineAuditEventKind.QuarantinePayloadMissing => RuntimeEventSeverity.Medium,
        QuarantineAuditEventKind.QuarantineFailed => RuntimeEventSeverity.Medium,
        QuarantineAuditEventKind.QuarantineRestoreFailed => RuntimeEventSeverity.Medium,
        _ => RuntimeEventSeverity.Informational,
    };
}
