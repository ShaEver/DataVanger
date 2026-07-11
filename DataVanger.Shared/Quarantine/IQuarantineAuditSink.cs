namespace DataVanger.Shared.Quarantine;

/// <summary>
/// Receives report-safe quarantine audit events. Sinks are passive observers:
/// they forward telemetry to the runtime event pipeline, reporting, or a test
/// collector. A sink NEVER classifies, NEVER quarantines, and NEVER confirms
/// malware. A throwing sink must not break a quarantine operation.
/// </summary>
public interface IQuarantineAuditSink
{
    void Publish(QuarantineAuditEvent auditEvent);
}
