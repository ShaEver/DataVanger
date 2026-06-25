using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.Shared.Status;

public enum ModuleOperatingState
{
    Active = 0,
    Passive = 1,
    AlertOnly = 2,
    Disabled = 3,
    Degraded = 4,
    Unavailable = 5,
    Unsupported = 6,
    NotImplemented = 7,
    TestOnly = 8,
    Experimental = 9,
    // Phase 18 taxonomy additions (appended for backward compatibility). Used by the
    // code-reality honest matrix; the legacy settings-driven catalog does not emit them.
    Prepared = 10,   // implementation/scaffolding exists but is not active/compiled/configured/validated
    Fallback = 11,   // a safe fallback implementation is in use instead of the real/prepared one
    Stub = 12,       // a placeholder exists but does not perform the real operation
}

public enum ProductHealthState
{
    Unknown = 0,
    Healthy = 1,
    Partial = 2,
    Degraded = 3,
    Disabled = 4,
    Unavailable = 5,
}

public sealed record ModuleStatus
{
    public ModuleStatus(
        string key,
        string displayName,
        ModuleOperatingState state,
        string detail,
        bool contributesToActiveProtection = false,
        bool isDevelopmentMode = false)
    {
        if (string.IsNullOrWhiteSpace(key))
            throw new ArgumentException("Module key must be non-empty.", nameof(key));
        if (string.IsNullOrWhiteSpace(displayName))
            throw new ArgumentException("Module display name must be non-empty.", nameof(displayName));

        Key = key.Trim();
        DisplayName = displayName.Trim();
        State = state;
        Detail = detail ?? string.Empty;
        ContributesToActiveProtection = contributesToActiveProtection && state == ModuleOperatingState.Active;
        IsDevelopmentMode = isDevelopmentMode;
    }

    public string Key { get; }
    public string DisplayName { get; }
    public ModuleOperatingState State { get; }
    public string Detail { get; }
    public bool ContributesToActiveProtection { get; }
    public bool IsDevelopmentMode { get; }

    public bool IsActiveProtection => State == ModuleOperatingState.Active && ContributesToActiveProtection;

    public bool IsOperational =>
        State is ModuleOperatingState.Active
            or ModuleOperatingState.Passive
            or ModuleOperatingState.AlertOnly
            or ModuleOperatingState.Experimental
            or ModuleOperatingState.TestOnly;
}

public sealed record ProductHealthSnapshot
{
    public ProductHealthSnapshot(
        ProductHealthState state,
        IReadOnlyList<ModuleStatus> modules,
        DateTimeOffset capturedAtUtc,
        IReadOnlyList<string>? warnings = null)
    {
        State = state;
        Modules = modules ?? Array.Empty<ModuleStatus>();
        CapturedAtUtc = capturedAtUtc;
        Warnings = warnings ?? Array.Empty<string>();
    }

    public ProductHealthState State { get; }
    public IReadOnlyList<ModuleStatus> Modules { get; }
    public DateTimeOffset CapturedAtUtc { get; }
    public IReadOnlyList<string> Warnings { get; }

    public int ActiveModuleCount => Modules.Count(m => m.State == ModuleOperatingState.Active);
    public int PassiveModuleCount => Modules.Count(m => m.State == ModuleOperatingState.Passive);
    public int AlertOnlyModuleCount => Modules.Count(m => m.State == ModuleOperatingState.AlertOnly);
    public int DisabledModuleCount => Modules.Count(m => m.State == ModuleOperatingState.Disabled);
    public int DegradedModuleCount => Modules.Count(m => m.State == ModuleOperatingState.Degraded);
    public int UnavailableModuleCount => Modules.Count(m =>
        m.State is ModuleOperatingState.Unavailable
            or ModuleOperatingState.Unsupported
            or ModuleOperatingState.NotImplemented);

    public bool HasActiveProtection => Modules.Any(m => m.IsActiveProtection);

    public bool IsFullyProtected =>
        Modules.Count > 0
        && Modules.All(m => m.IsActiveProtection)
        && DegradedModuleCount == 0
        && DisabledModuleCount == 0
        && UnavailableModuleCount == 0
        && PassiveModuleCount == 0
        && AlertOnlyModuleCount == 0;

    public static ProductHealthSnapshot FromModules(
        IEnumerable<ModuleStatus> modules,
        DateTimeOffset? capturedAtUtc = null,
        IEnumerable<string>? warnings = null)
    {
        var moduleList = modules?.ToArray() ?? Array.Empty<ModuleStatus>();
        var warningList = warnings?.Where(w => !string.IsNullOrWhiteSpace(w)).ToArray() ?? Array.Empty<string>();
        return new ProductHealthSnapshot(
            DetermineState(moduleList),
            moduleList,
            capturedAtUtc ?? DateTimeOffset.UtcNow,
            warningList);
    }

    private static ProductHealthState DetermineState(IReadOnlyList<ModuleStatus> modules)
    {
        if (modules.Count == 0) return ProductHealthState.Unknown;
        if (modules.Any(m => m.State == ModuleOperatingState.Degraded)) return ProductHealthState.Degraded;
        if (modules.All(m => m.State == ModuleOperatingState.Disabled)) return ProductHealthState.Disabled;
        if (modules.All(m => m.State is ModuleOperatingState.Unavailable or ModuleOperatingState.Unsupported or ModuleOperatingState.NotImplemented))
            return ProductHealthState.Unavailable;
        if (modules.Any(m => !m.IsOperational)) return ProductHealthState.Partial;
        if (modules.All(m => m.IsActiveProtection)) return ProductHealthState.Healthy;
        return ProductHealthState.Partial;
    }
}

public sealed record ModuleStatusViewModel(
    string Name,
    string State,
    string Detail,
    bool IsActiveProtection);

public sealed record ProductHealthViewModel(
    string ProductName,
    string State,
    bool HasActiveProtection,
    bool IsFullyProtected,
    IReadOnlyList<ModuleStatusViewModel> Modules)
{
    public static ProductHealthViewModel FromSnapshot(ProductHealthSnapshot snapshot)
    {
        var safeSnapshot = snapshot ?? ProductHealthSnapshot.FromModules(Array.Empty<ModuleStatus>());
        return new ProductHealthViewModel(
            "DataVanger",
            safeSnapshot.State.ToString(),
            safeSnapshot.HasActiveProtection,
            safeSnapshot.IsFullyProtected,
            safeSnapshot.Modules
                .Select(m => new ModuleStatusViewModel(m.DisplayName, m.State.ToString(), m.Detail, m.IsActiveProtection))
                .ToArray());
    }
}

/// <summary>
/// Phase 18 — honest, code-reality module-state matrix. Reports what is actually
/// Active / Prepared / Fallback / Disabled / Stub / Degraded in the current codebase,
/// so the UI and operators never over-trust prepared/stub/fallback systems.
///
/// This is descriptive only: producing the matrix performs NO I/O, starts no modules,
/// writes no settings, and triggers no scans/services/updates. Uncertainty
/// (e.g. "Needs hardening" / "Needs audit") is expressed in the Detail text, not by
/// over-claiming Active. The real-libyara entry is derived from the YARA_REAL compile
/// symbol; the rest reflect verified code facts (e.g. HttpUpdateTransport throws;
/// the service mode is a diagnostic stub; ETW/AMSI adapters report IsAvailable=false).
/// </summary>
public static class CodeRealityModuleMatrix
{
    public static IReadOnlyList<ModuleStatus> Create()
    {
        return new List<ModuleStatus>
        {
            new("scan-engine", "Scan engine", ModuleOperatingState.Active,
                "5-phase on-demand/scheduled scan pipeline."),
            new("detection-pipeline", "Detection pipeline", ModuleOperatingState.Active,
                "Hash/heuristic/script/PE/archive/document/browser-extension/YARA/persistence modules, exception-isolated."),
            new("pe-detection", "PE detection", ModuleOperatingState.Active,
                "PE static analysis module."),
            new("pe-section-entropy", "PE section entropy", ModuleOperatingState.Active,
                "Per-section Shannon entropy; descriptive-only (Score 0, never confirms malware)."),
            new("yara-lightweight", "YARA detection (lightweight engine)", ModuleOperatingState.Fallback,
                "Active LightweightYaraDatabase via YaraEngineAdapter — the guaranteed fallback used because the real libyara backend is not active. Curated confirmed-rule semantics preserved."),
#if YARA_REAL
            new("real-libyara", "Real libyara backend", ModuleOperatingState.Prepared,
                "Compiled with YARA_REAL, but requires a verified dnYara package + Windows restore/build/rule validation before it can be Active."),
#else
            new("real-libyara", "Real libyara backend", ModuleOperatingState.Prepared,
                "Not compiled (no YARA_REAL symbol / no active dnYara package); LibyaraEngine.TryCreate returns null and the LightweightYaraDatabase fallback is used."),
#endif
            new("trusted-publishers", "Trusted publishers", ModuleOperatingState.Active,
                "Configurable substring-match policy (no OpenAI/Wondershare/SweetLabs by default). Certificate-chain/thumbprint validation is NOT implemented — Needs hardening. A trusted signature never overrides a known-malicious hash."),
            new("reputation-engine", "Reputation engine", ModuleOperatingState.Active,
                "Trust-state scoring; blacklist precedence over allowlist preserved."),
            new("quarantine-v2", "Secure Quarantine V2", ModuleOperatingState.Active,
                "Authenticated encryption + HMAC + (Windows) DPAPI key; integrity-verified restore; automatic action ConfirmedMalware-only; restore never automatic."),
            new("scheduler", "Scheduler", ModuleOperatingState.Active,
                "Deterministic tick-driven scheduler; reading status starts no loops."),
            new("realtime-protection", "Real-time protection", ModuleOperatingState.Prepared,
                "Conservative decision engine is implemented & tested (authorizes auto-action only for ConfirmedMalware); the resident runtime depends on the stubbed Windows service and is not active."),
            new("signed-update-verification", "Signed update verification", ModuleOperatingState.Active,
                "RSA-PSS / ECDsa manifest verification + anti-downgrade implemented & tested. Verification only — not network delivery."),
            new("http-update-transport", "HTTP update transport", ModuleOperatingState.Stub,
                "HttpUpdateTransport throws NotSupportedException; no network update transport is active."),
            new("windows-service", "Windows service mode", ModuleOperatingState.Stub,
                "--service is a diagnostic stub; no install/start/stop service lifecycle exists."),
            new("named-pipe-ipc", "Named-pipe IPC (local)", ModuleOperatingState.Active,
                "Local named-pipe IPC with payload allowlist/size validation. Local-only."),
            new("ipc-acl-hardening", "IPC ACL hardening", ModuleOperatingState.Prepared,
                "Not implemented — Needs hardening: no Windows ACL / security-descriptor restriction on the pipe (payload validation exists, connection-level ACLs do not)."),
            new("etw-provider", "ETW provider", ModuleOperatingState.Stub,
                "Behavior adapter reports IsAvailable=false; Null/InMemory providers are in use. The real WindowsEtwRuntimeProvider is prepared but not active."),
            new("amsi-adapter", "AMSI adapter", ModuleOperatingState.Stub,
                "AMSI behavior adapter reports IsAvailable=false; no real amsi.dll integration. Telemetry-only when present; never confirms malware alone."),
            new("memory-scanner", "Memory scanner", ModuleOperatingState.Active,
                "Memory scanner engine is implemented & tested; memory evidence alone is not ConfirmedMalware. (Wiring into the per-file scan composition: Needs audit.)"),
            new("behavioral-engine", "Behavioral engine", ModuleOperatingState.Active,
                "Evidence/telemetry-only behavioral correlation, clamped — never ConfirmedMalware alone. (Wiring into the per-file scan composition: Needs audit.)"),
            new("module-status-ui", "Module status UI", ModuleOperatingState.Active,
                "Read-only honest module-state panel (this surface). No writes, no module activation, no scans."),
            new("settings-ui", "Settings UI", ModuleOperatingState.Active,
                "Settings window exposes user-editable configuration (read/save)."),
            new("reporting-forensics", "Reporting and forensics", ModuleOperatingState.Active,
                "CSV/TXT/HTML/JSON report exporters; never promote heuristic-only evidence to ConfirmedMalware."),
            new("xunit-tests", "xUnit test suite", ModuleOperatingState.Active,
                "xUnit suite (requires Windows + .NET 8 SDK to build/run)."),
            new("legacy-parity-tests", "LegacyParityTests", ModuleOperatingState.Active,
                "Faithful-wrapper mega-Fact plus extracted Phase-2 classes (Quarantine/ModuleStatus/Update/ServiceIpc)."),
            new("antifp-tests", "AntiFalsePositive tests", ModuleOperatingState.Active,
                "Dedicated anti-false-positive / classification Facts."),
            new("publisher-tests", "Publisher tests", ModuleOperatingState.Active,
                "Dedicated trusted-publisher Facts."),
            new("yara-tests", "Yara tests", ModuleOperatingState.Active,
                "Dedicated YARA fallback Facts."),
        };
    }
}
