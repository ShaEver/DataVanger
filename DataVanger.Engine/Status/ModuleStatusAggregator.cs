using System;
using System.Collections.Generic;
using System.Linq;
using DataVanger.Shared.Settings;
using DataVanger.Shared.Status;

namespace DataVanger.Engine.Status;

public interface IModuleStatusProvider
{
    ModuleStatus GetStatus();
}

public sealed class StaticModuleStatusProvider : IModuleStatusProvider
{
    private readonly ModuleStatus _status;

    public StaticModuleStatusProvider(ModuleStatus status)
    {
        _status = status ?? throw new ArgumentNullException(nameof(status));
    }

    public ModuleStatus GetStatus() => _status;
}

public sealed class ModuleStatusAggregator
{
    private readonly IReadOnlyList<IModuleStatusProvider?> _providers;

    public ModuleStatusAggregator(IEnumerable<IModuleStatusProvider?> providers)
    {
        _providers = providers?.ToArray() ?? Array.Empty<IModuleStatusProvider?>();
    }

    public IReadOnlyList<ModuleStatus> GetModuleStatuses()
    {
        var statuses = new List<ModuleStatus>(_providers.Count);
        foreach (var provider in _providers)
        {
            if (provider is null)
            {
                statuses.Add(new ModuleStatus(
                    "null-provider",
                    "Null status provider",
                    ModuleOperatingState.TestOnly,
                    "A null/test provider was supplied; it is not active protection."));
                continue;
            }

            try
            {
                statuses.Add(provider.GetStatus());
            }
            catch (Exception ex)
            {
                statuses.Add(new ModuleStatus(
                    provider.GetType().Name,
                    provider.GetType().Name,
                    ModuleOperatingState.Degraded,
                    "Status provider failed without starting runtime components: " + ex.GetType().Name));
            }
        }

        return statuses;
    }

    public ProductHealthSnapshot GetProductHealthSnapshot(DateTimeOffset? capturedAtUtc = null)
        => ProductHealthSnapshot.FromModules(GetModuleStatuses(), capturedAtUtc);
}

public static class DefaultModuleStatusCatalog
{
    public static IReadOnlyList<IModuleStatusProvider> CreateProviders(DataVangerSettings? settings = null)
    {
        var phase09Settings = DataVangerSettingsValidator.Validate(settings).EffectiveSettings;
        var phase09EtwState = phase09Settings.EtwTelemetryRequested
            ? phase09Settings.EtwProviderSupported ? ModuleOperatingState.Passive : ModuleOperatingState.Unavailable
            : ModuleOperatingState.Disabled;
        var phase09RealtimeState = phase09Settings.ActiveRealtimeProtectionRequested
            ? phase09Settings.ServiceAvailable ? ModuleOperatingState.Passive : ModuleOperatingState.Degraded
            : ModuleOperatingState.Disabled;
        var phase09ProtectedFilesState = phase09Settings.ProtectedFilesActivityRequested
            ? phase09Settings.RuntimeEventPipelineEnabled ? ModuleOperatingState.AlertOnly : ModuleOperatingState.Degraded
            : ModuleOperatingState.Disabled;
        var phase09SelfProtectionState = phase09Settings.SelfProtectionRequested
            ? phase09Settings.DevelopmentMode ? ModuleOperatingState.Passive : ModuleOperatingState.Experimental
            : ModuleOperatingState.Disabled;

        return new IModuleStatusProvider[]
        {
            Provider("scanner", "Scanner", ModuleOperatingState.Active,
                "On-demand scanner is available; it does not imply resident protection.", contributesToActiveProtection: false),
            Provider("realtime-file-protection", "Real-time file protection", phase09RealtimeState,
                phase09RealtimeState == ModuleOperatingState.Degraded
                    ? "Requested, but the service host is unavailable; no watcher is started by status reads."
                    : "Resident blocking is not started by status reads."),
            Provider("windows-service-host", "Windows service host",
                phase09Settings.ServiceAvailable ? ModuleOperatingState.Passive : ModuleOperatingState.Unavailable,
                "Service lifecycle surface only; status reads do not install or start the service."),
            Provider("runtime-event-pipeline", "Runtime Event Pipeline",
                phase09Settings.RuntimeEventPipelineEnabled ? ModuleOperatingState.Passive : ModuleOperatingState.Disabled,
                "Pipeline is a passive event surface; status reads do not create background loops."),
            Provider("etw-telemetry", "ETW telemetry", phase09EtwState,
                phase09EtwState == ModuleOperatingState.Unavailable
                    ? "Requested, but ETW is unsupported/unavailable in this environment."
                    : "ETW collection is not started by status reads."),
            Provider("behavioral-runtime-binding", "Behavioral runtime binding", ModuleOperatingState.AlertOnly,
                "Evidence-only behavioral binding; never creates ConfirmedMalware verdicts."),
            Provider("protected-files-activity", "Protected Files Activity Monitor", phase09ProtectedFilesState,
                "Alert-only protected-file activity evidence; no quarantine or active response from status reads."),
            Provider("secure-quarantine-v2", "Secure Quarantine V2", ModuleOperatingState.Active,
                "Authenticated quarantine storage is implemented; automatic action remains ConfirmedMalware-only."),
            Provider("updates", "Updates", ModuleOperatingState.NotImplemented,
                "Signed Updates are not implemented/configured in Phase 09; signature hash updates remain separate."),
            Provider("self-protection", "Self-protection", phase09SelfProtectionState,
                phase09Settings.DevelopmentMode
                    ? "Development-safe/passive; no watchdog or tamper response is started by status reads."
                    : "Experimental status only; no future hardening behavior is implemented here."),
            Provider("scheduler", "Scheduler", ModuleOperatingState.Passive,
                "Scheduler models are available; status reads do not start scheduling loops."),
            Provider("reporting-forensics", "Reporting and Forensics", ModuleOperatingState.Active,
                "Report/forensics exporters are available and never promote heuristic-only evidence to ConfirmedMalware."),
            Provider("browser-extension-intelligence", "Browser Extension Intelligence", ModuleOperatingState.Active,
                "Browser extension analysis is available as heuristic intelligence only."),
            Provider("reputation-engine", "Reputation Engine", ModuleOperatingState.Active,
                "Reputation analysis is available and preserves blacklist precedence over allowlist downgrades."),
            Provider("memory-scanner", "Memory Scanner", ModuleOperatingState.Active,
                "Memory scanner analysis is available; memory evidence alone is not ConfirmedMalware."),
            Provider("amsi-like-analysis", "AMSI-like analysis", ModuleOperatingState.AlertOnly,
                "AMSI-like content analysis is telemetry/evidence only and degrades gracefully when unavailable."),
        };
    }

    /// <summary>
    /// Phase 18 — the honest, code-reality module-state matrix (Active / Prepared /
    /// Fallback / Disabled / Stub / Degraded). Pure and descriptive: it starts nothing,
    /// writes nothing, and triggers no scans/services/updates. Delegates to the shared
    /// <see cref="CodeRealityModuleMatrix"/> so the UI (which references only Shared) and
    /// Engine consumers report identical states. Does not alter the legacy settings-driven
    /// <see cref="CreateProviders"/> catalog.
    /// </summary>
    public static IReadOnlyList<ModuleStatus> CreateCodeRealityModules()
        => CodeRealityModuleMatrix.Create();

    private static IModuleStatusProvider Provider(
        string key,
        string displayName,
        ModuleOperatingState state,
        string detail,
        bool contributesToActiveProtection = false)
        => new StaticModuleStatusProvider(new ModuleStatus(
            key,
            displayName,
            state,
            detail,
            contributesToActiveProtection));
}
