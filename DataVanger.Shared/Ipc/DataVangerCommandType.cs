namespace DataVanger.Shared.Ipc;

/// <summary>
/// Phase 11 (Service IPC and UI Integration): the complete, closed
/// allowlist of commands the desktop UI may send to the resident service.
///
/// The enum is intentionally narrow. It exposes only safe, bounded,
/// request/response operations. Remediation is exposed only as a narrow,
/// policy-gated DTO command; the catalog NEVER exposes arbitrary engine
/// methods, arbitrary file execution, or arbitrary shell execution.
///
/// Anti-FP note: no command on this list classifies a file or process as
/// ConfirmedMalware. Remediation commands consume an existing band and fail
/// closed when policy/consent does not authorize execution.
/// </summary>
public enum DataVangerCommandType
{
    /// <summary>Unknown / unset. Always rejected by the router.</summary>
    Unknown = 0,

    // ── Status ──────────────────────────────────────────────────────────
    GetServiceStatus,
    GetModuleStatus,
    GetProtectionStatus,
    GetRecentEvents,
    GetConfigurationSummary,

    // ── Protection control ─────────────────────────────────────────────
    PauseRealtimeProtection,
    ResumeRealtimeProtection,

    // ── Scan requests ──────────────────────────────────────────────────
    StartQuickScan,
    StartCustomScan,
    CancelScan,
    GetScanStatus,

    // ── Quarantine requests ────────────────────────────────────────────
    ListQuarantineItems,
    GetQuarantineItemDetails,
    RestoreQuarantineItem,
    DeleteQuarantineItem,

    // ── Remediation requests ───────────────────────────────────────────
    ExecuteRemediationAction,

    // ── Update requests ────────────────────────────────────────────────
    CheckForUpdates,
    GetUpdateStatus,

    // ── Diagnostics ────────────────────────────────────────────────────
    ExportDiagnosticBundle,
    Ping,

    /// <summary>
    /// Stops an in-memory / development / test host ONLY. The router refuses
    /// this command for a production service host. It must never stop or
    /// disable a real installed Windows Service.
    /// </summary>
    ShutdownDevelopmentHost,
}
