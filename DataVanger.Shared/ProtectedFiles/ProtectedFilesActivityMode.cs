namespace DataVanger.Shared.ProtectedFiles;

/// <summary>
/// Operating mode of the Protected Files Activity Monitor (Phase 2 /
/// Step 07).
///
/// CRITICAL: every mode in this phase is passive. None of these modes
/// quarantine, kill, suspend, block writes, or remediate. The mode only
/// changes how much analysis/alerting happens and how the monitor labels
/// its reported state. There is no destructive mode in this phase.
/// </summary>
public enum ProtectedFilesActivityMode
{
    /// <summary>No analysis; the monitor subscribes to nothing and emits no evidence.</summary>
    Disabled = 0,

    /// <summary>Analyze and produce evidence/health for reporting only. Never acts.</summary>
    Passive = 1,

    /// <summary>
    /// Analyze and surface alerts (evidence + optional reporting telemetry).
    /// Still never blocks or remediates — alerting is the only difference
    /// from <see cref="Passive"/>.
    /// </summary>
    AlertOnly = 2,

    /// <summary>Development-safe defaults: deterministic, disposable, never acts.</summary>
    Development = 3,

    /// <summary>Deterministic test mode: no background loops, no OS dependency.</summary>
    Test = 4,
}
