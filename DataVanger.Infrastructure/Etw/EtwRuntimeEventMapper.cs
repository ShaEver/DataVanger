using System;
using System.Collections.Generic;
using DataVanger.Shared.Etw;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Infrastructure.Etw;

/// <summary>
/// Central, side-effect-free mapper from raw ETW observations into
/// normalized <see cref="RuntimeSecurityEvent"/> instances introduced
/// in Phase 2 Step 05 (ETW Real Provider).
///
/// All command-line handling for ETW telemetry flows through this
/// mapper, which in turn defers to <see cref="EtwCommandLineSanitizer"/>
/// for redaction. That centralization is the redaction boundary
/// required by the phase spec.
///
/// Anti-FP guarantee:
///   - Emits <see cref="RuntimeEventSource.EtwTelemetry"/> for source,
///     so downstream consumers can tell that a verdict was NOT made by
///     the scanner.
///   - Defaults severity to Informational. Indicator-driven escalation
///     never exceeds Low here — verdicts originate elsewhere.
///   - Sets no quarantine, no remediation, no malware classification.
/// </summary>
public static class EtwRuntimeEventMapper
{
    public const string MetaProviderName    = "etw.provider";
    public const string MetaRawEventName    = "etw.event";
    public const string MetaImagePath       = "etw.image_path";
    public const string MetaCommandLine     = "etw.command_line";
    public const string MetaCommandLineLen  = "etw.command_line.length";
    public const string MetaSanitized       = "etw.command_line.sanitized";
    public const string MetaIndicatorPrefix = "etw.indicator.";

    /// <summary>
    /// Map a process-start observation. Returns null when the
    /// observation is unusable (no PID at all). Never throws.
    /// </summary>
    public static RuntimeSecurityEvent? MapProcessStart(
        EtwProcessStartObservation observation,
        EtwProviderConfiguration configuration)
    {
        if (observation is null || configuration is null) return null;
        if (observation.ProcessId <= 0) return null;

        var meta = new Dictionary<string, string>(StringComparer.Ordinal);
        SetIfPresent(meta, MetaProviderName, observation.RawProviderName);
        SetIfPresent(meta, MetaRawEventName, observation.RawEventName ?? "Process/Start");
        SetIfPresent(meta, MetaImagePath, observation.ImagePath);

        string? sanitizedCli = null;
        if (configuration.CaptureCommandLine && !string.IsNullOrEmpty(observation.CommandLine))
        {
            sanitizedCli = configuration.SanitizeCommandLines
                ? EtwCommandLineSanitizer.Sanitize(observation.CommandLine)
                : observation.CommandLine;
            if (!string.IsNullOrEmpty(sanitizedCli))
            {
                meta[MetaCommandLine] = sanitizedCli!;
                meta[MetaCommandLineLen] = sanitizedCli!.Length.ToString();
                meta[MetaSanitized] = configuration.SanitizeCommandLines ? "true" : "false";
            }
        }

        var severity = RuntimeEventSeverity.Informational;

        if (configuration.CapturePowerShellSignals)
        {
            var tags = EtwPowerShellIndicators.DetectIndicators(observation.ProcessName, sanitizedCli ?? observation.CommandLine);
            foreach (var tag in tags)
            {
                meta[MetaIndicatorPrefix + tag] = "true";
            }
            // Conservative bump only — never above Low, NEVER a verdict.
            if (tags.Count >= 2) severity = RuntimeEventSeverity.Low;
        }

        return new RuntimeSecurityEvent
        {
            Source = RuntimeEventSource.EtwTelemetry,
            Category = RuntimeEventCategory.ProcessCreated,
            Severity = severity,
            Title = "ETW process start",
            Description = BuildProcessDescription(observation),
            ProcessId = observation.ProcessId,
            ProcessName = observation.ProcessName,
            ParentProcessId = observation.ParentProcessId,
            SubjectPath = observation.ImagePath,
            TimestampUtc = observation.TimestampUtc == default ? DateTimeOffset.UtcNow : observation.TimestampUtc,
            Metadata = meta,
        };
    }

    /// <summary>
    /// Map a stand-alone command-line observation (used by InMemory
    /// provider tests and any backend that surfaces command lines
    /// after the process-start event).
    /// </summary>
    public static RuntimeSecurityEvent? MapCommandLine(
        EtwCommandLineObservation observation,
        EtwProviderConfiguration configuration)
    {
        if (observation is null || configuration is null) return null;
        if (!configuration.CaptureCommandLine) return null;
        if (observation.ProcessId <= 0) return null;
        if (string.IsNullOrEmpty(observation.CommandLine)) return null;

        var sanitized = configuration.SanitizeCommandLines
            ? EtwCommandLineSanitizer.Sanitize(observation.CommandLine)
            : observation.CommandLine;

        var meta = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [MetaCommandLine]    = sanitized,
            [MetaCommandLineLen] = sanitized.Length.ToString(),
            [MetaSanitized]      = configuration.SanitizeCommandLines ? "true" : "false",
        };
        SetIfPresent(meta, MetaProviderName, observation.RawProviderName);
        SetIfPresent(meta, MetaRawEventName, observation.RawEventName ?? "Process/CommandLine");

        var severity = RuntimeEventSeverity.Informational;

        if (configuration.CapturePowerShellSignals)
        {
            var tags = EtwPowerShellIndicators.DetectIndicators(observation.ProcessName, sanitized);
            foreach (var tag in tags)
            {
                meta[MetaIndicatorPrefix + tag] = "true";
            }
            if (tags.Count >= 2) severity = RuntimeEventSeverity.Low;
        }

        return new RuntimeSecurityEvent
        {
            Source = RuntimeEventSource.EtwTelemetry,
            Category = RuntimeEventCategory.CommandLineObserved,
            Severity = severity,
            Title = "ETW command line observed",
            Description = string.IsNullOrEmpty(observation.ProcessName)
                ? $"ETW command line for pid={observation.ProcessId}"
                : $"ETW command line for {observation.ProcessName} (pid={observation.ProcessId})",
            ProcessId = observation.ProcessId,
            ProcessName = observation.ProcessName,
            TimestampUtc = observation.TimestampUtc == default ? DateTimeOffset.UtcNow : observation.TimestampUtc,
            Metadata = meta,
        };
    }

    /// <summary>
    /// Map a provider-internal health/error observation (start, stop,
    /// degrade, recover). Allows the ETW provider to surface its own
    /// lifecycle into the runtime event pipeline without bypassing it.
    /// </summary>
    public static RuntimeSecurityEvent MapHealth(string providerName, EtwProviderStatus status, string? message)
    {
        var meta = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [MetaProviderName] = providerName ?? string.Empty,
            ["etw.status"]    = status.ToString(),
        };

        var severity = status switch
        {
            EtwProviderStatus.Running             => RuntimeEventSeverity.Informational,
            EtwProviderStatus.Stopped             => RuntimeEventSeverity.Informational,
            EtwProviderStatus.Starting            => RuntimeEventSeverity.Informational,
            EtwProviderStatus.Disabled            => RuntimeEventSeverity.Informational,
            EtwProviderStatus.NotConfigured       => RuntimeEventSeverity.Informational,
            EtwProviderStatus.UnsupportedPlatform => RuntimeEventSeverity.Low,
            EtwProviderStatus.PermissionDenied    => RuntimeEventSeverity.Low,
            EtwProviderStatus.ProviderUnavailable => RuntimeEventSeverity.Low,
            EtwProviderStatus.Degraded            => RuntimeEventSeverity.Medium,
            EtwProviderStatus.Faulted             => RuntimeEventSeverity.Medium,
            _                                     => RuntimeEventSeverity.Informational,
        };

        return new RuntimeSecurityEvent
        {
            Source = RuntimeEventSource.EtwTelemetry,
            Category = RuntimeEventCategory.HealthStatus,
            Severity = severity,
            Title = $"ETW provider {status}",
            Description = string.IsNullOrEmpty(message) ? $"ETW provider '{providerName}' status: {status}" : message!,
            Metadata = meta,
            TimestampUtc = DateTimeOffset.UtcNow,
        };
    }

    private static void SetIfPresent(IDictionary<string, string> meta, string key, string? value)
    {
        if (string.IsNullOrEmpty(value)) return;
        meta[key] = value!;
    }

    private static string BuildProcessDescription(EtwProcessStartObservation o)
    {
        if (!string.IsNullOrEmpty(o.ProcessName) && o.ParentProcessId is int ppid)
        {
            return $"ETW observed process start {o.ProcessName} (pid={o.ProcessId}, ppid={ppid})";
        }
        if (!string.IsNullOrEmpty(o.ProcessName))
        {
            return $"ETW observed process start {o.ProcessName} (pid={o.ProcessId})";
        }
        return $"ETW observed process start pid={o.ProcessId}";
    }
}

/// <summary>
/// Raw, transport-neutral observation of a process-start ETW event.
/// Producers (InMemory provider, future Windows backend) fill this
/// in once and let the mapper handle normalization, sanitization,
/// and indicator tagging.
/// </summary>
public sealed class EtwProcessStartObservation
{
    public int ProcessId { get; init; }
    public int? ParentProcessId { get; init; }
    public string? ProcessName { get; init; }
    public string? ImagePath { get; init; }
    public string? CommandLine { get; init; }
    public DateTimeOffset TimestampUtc { get; init; }
    public string? RawProviderName { get; init; }
    public string? RawEventName { get; init; }
}

/// <summary>
/// Raw, transport-neutral observation of a process command-line ETW
/// event surfaced separately from process-start.
/// </summary>
public sealed class EtwCommandLineObservation
{
    public int ProcessId { get; init; }
    public string? ProcessName { get; init; }
    public string CommandLine { get; init; } = string.Empty;
    public DateTimeOffset TimestampUtc { get; init; }
    public string? RawProviderName { get; init; }
    public string? RawEventName { get; init; }
}
