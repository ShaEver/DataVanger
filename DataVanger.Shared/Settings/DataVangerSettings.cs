using System;
using System.Collections.Generic;
using System.Linq;

namespace DataVanger.Shared.Settings;

public enum SettingsIssueSeverity
{
    Warning = 0,
    Invalid = 1,
}

public sealed record SettingsValidationIssue(
    string Code,
    SettingsIssueSeverity Severity,
    string Message);

public sealed record UpdateSettings
{
    public bool SignedUpdateValidationRequested { get; init; }
    public bool SignedUpdatesImplemented { get; init; }
    public bool SignedUpdatesConfigured { get; init; }
}

public sealed record DataVangerSettings
{
    public bool DevelopmentMode { get; init; } = true;
    public bool ActiveRealtimeProtectionRequested { get; init; }
    public bool ServiceAvailable { get; init; }
    public bool EtwTelemetryRequested { get; init; }
    public bool EtwProviderSupported { get; init; }
    public bool RuntimeEventPipelineEnabled { get; init; } = true;
    public bool ProtectedFilesActivityRequested { get; init; }
    public bool AutomaticQuarantineRequested { get; init; }
    public bool AutomaticQuarantineForNonConfirmedMalwareRequested { get; init; }
    public bool SelfProtectionRequested { get; init; }
    public UpdateSettings Updates { get; init; } = new();

    public static DataVangerSettings DevelopmentSafeDefaults() => new()
    {
        DevelopmentMode = true,
        RuntimeEventPipelineEnabled = true,
        EtwProviderSupported = OperatingSystem.IsWindows(),
    };
}

public sealed record SettingsValidationResult
{
    public SettingsValidationResult(
        DataVangerSettings effectiveSettings,
        IReadOnlyList<SettingsValidationIssue> issues)
    {
        EffectiveSettings = effectiveSettings ?? DataVangerSettings.DevelopmentSafeDefaults();
        Issues = issues ?? Array.Empty<SettingsValidationIssue>();
    }

    public DataVangerSettings EffectiveSettings { get; }
    public IReadOnlyList<SettingsValidationIssue> Issues { get; }
    public bool HasWarnings => Issues.Count > 0;
    public bool IsValid => Issues.All(i => i.Severity != SettingsIssueSeverity.Invalid);
}

public sealed record SettingsViewModel(
    bool DevelopmentMode,
    bool ActiveRealtimeProtectionRequested,
    bool EtwTelemetryRequested,
    bool ProtectedFilesActivityRequested,
    bool AutomaticQuarantineRequested,
    bool SignedUpdateValidationRequested,
    IReadOnlyList<string> Warnings)
{
    public static SettingsViewModel FromValidation(SettingsValidationResult result)
    {
        var safeResult = result ?? DataVangerSettingsValidator.Validate(null);
        var effective = safeResult.EffectiveSettings;
        return new SettingsViewModel(
            effective.DevelopmentMode,
            effective.ActiveRealtimeProtectionRequested,
            effective.EtwTelemetryRequested,
            effective.ProtectedFilesActivityRequested,
            effective.AutomaticQuarantineRequested,
            effective.Updates.SignedUpdateValidationRequested,
            safeResult.Issues.Select(i => i.Message).ToArray());
    }
}

public static class DataVangerSettingsValidator
{
    public static SettingsValidationResult Validate(DataVangerSettings? settings)
    {
        var effective = settings ?? DataVangerSettings.DevelopmentSafeDefaults();
        var issues = new List<SettingsValidationIssue>();

        if (effective.ActiveRealtimeProtectionRequested && !effective.ServiceAvailable)
        {
            issues.Add(new SettingsValidationIssue(
                "ServiceUnavailable",
                SettingsIssueSeverity.Warning,
                "Active real-time protection was requested, but the service host is unavailable; status is degraded."));
        }

        if (effective.EtwTelemetryRequested && !effective.EtwProviderSupported)
        {
            issues.Add(new SettingsValidationIssue(
                "EtwUnavailable",
                SettingsIssueSeverity.Warning,
                "ETW telemetry was requested, but the ETW provider is unsupported or unavailable; status is degraded."));
        }

        if (effective.ProtectedFilesActivityRequested && !effective.RuntimeEventPipelineEnabled)
        {
            issues.Add(new SettingsValidationIssue(
                "ProtectedFilesNeedsRuntimePipeline",
                SettingsIssueSeverity.Warning,
                "Protected Files Activity requires the Runtime Event Pipeline; the monitor is downgraded to alert-only/unavailable."));
        }

        if (effective.AutomaticQuarantineForNonConfirmedMalwareRequested)
        {
            issues.Add(new SettingsValidationIssue(
                "AutomaticQuarantineConfirmedOnly",
                SettingsIssueSeverity.Invalid,
                "Automatic quarantine cannot be enabled for non-confirmed malware; it is safely downgraded to ConfirmedMalware-only."));
            effective = effective with { AutomaticQuarantineForNonConfirmedMalwareRequested = false };
        }

        if (effective.Updates.SignedUpdateValidationRequested
            && (!effective.Updates.SignedUpdatesImplemented || !effective.Updates.SignedUpdatesConfigured))
        {
            issues.Add(new SettingsValidationIssue(
                "SignedUpdatesNotConfigured",
                SettingsIssueSeverity.Warning,
                "Signed update validation was requested before Signed Updates are implemented/configured; update status remains NotImplemented/NotConfigured."));
            effective = effective with
            {
                Updates = effective.Updates with
                {
                    SignedUpdateValidationRequested = false,
                },
            };
        }

        if (effective.SelfProtectionRequested && effective.DevelopmentMode)
        {
            issues.Add(new SettingsValidationIssue(
                "SelfProtectionDevelopmentMode",
                SettingsIssueSeverity.Warning,
                "Self-protection was requested in development mode; it is safely downgraded to passive."));
        }

        return new SettingsValidationResult(effective, issues);
    }
}
