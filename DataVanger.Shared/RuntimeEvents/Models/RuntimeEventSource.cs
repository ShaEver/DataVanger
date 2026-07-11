namespace DataVanger.Shared.RuntimeEvents;

/// <summary>
/// Producer that emitted a <see cref="RuntimeSecurityEvent"/>. The enum
/// is intentionally broad so future runtime modules (ETW, AMSI, anti-
/// ransomware, behavioral, reporting, UI, service host) can publish
/// through the same pipeline without growing tightly-coupled APIs.
///
/// Anti-FP note: the source has no classification authority. A
/// <see cref="RealtimeFileProtection"/> event is telemetry, not a
/// malware verdict.
/// </summary>
public enum RuntimeEventSource
{
    Unknown = 0,
    RealtimeFileProtection,
    ScanEngine,
    BehavioralEngine,
    MemoryScanner,
    EtwTelemetry,
    AmsiContentAnalysis,
    ReputationEngine,
    BrowserExtensionIntelligence,
    Scheduler,
    Reporting,
    Forensics,
    SelfProtection,
    AntiRansomware,
    Quarantine,
    UpdateManager,
    ServiceHost,
    Ui,
    TestHarness,
}
