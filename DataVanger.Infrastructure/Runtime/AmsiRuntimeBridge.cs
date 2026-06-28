using System;
using System.Collections.Generic;
using System.Threading;
using DataVanger.Runtime.Amsi;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Runtime;

/// <summary>
/// Converts in-memory AMSI telemetry into ScriptObserved events on the
/// resident runtime pipeline. It observes only explicitly submitted content;
/// it does not patch amsi.dll, register a system provider, or block scripts.
/// </summary>
public sealed class AmsiRuntimeBridge : IDisposable
{
    private const string IndicatorPrefix = "etw.indicator.";
    private readonly IAmsiTelemetryProvider _provider;
    private readonly IRuntimeEventPublisher _publisher;
    private readonly Action<string>? _diagnostics;
    private long _published;
    private long _failed;
    private int _disposed;

    public AmsiRuntimeBridge(
        IAmsiTelemetryProvider provider,
        IRuntimeEventPublisher publisher,
        Action<string>? diagnostics = null)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _publisher = publisher ?? throw new ArgumentNullException(nameof(publisher));
        _diagnostics = diagnostics;
        _provider.EventReceived += OnEventReceived;
    }

    public long PublishedCount => Interlocked.Read(ref _published);
    public long FailedCount => Interlocked.Read(ref _failed);

    private void OnEventReceived(RuntimeTelemetryEvent runtimeEvent)
    {
        if (runtimeEvent is null || Volatile.Read(ref _disposed) != 0) return;

        try
        {
            _publisher.PublishAsync(Map(runtimeEvent), CancellationToken.None).GetAwaiter().GetResult();
            Interlocked.Increment(ref _published);
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _failed);
            TryDiagnose($"amsi-runtime bridge publish failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    public static RuntimeSecurityEvent Map(RuntimeTelemetryEvent runtimeEvent)
    {
        if (runtimeEvent is null) throw new ArgumentNullException(nameof(runtimeEvent));

        var tag = NormalizeIndicator(runtimeEvent.ExtraTag);
        var metadata = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [IndicatorPrefix + tag] = "true",
            ["amsi.provider"] = runtimeEvent.ProviderName,
            ["amsi.content_length"] = runtimeEvent.ScriptContent.Length.ToString(),
        };

        // Keep the provider's original indicator and add the shared runtime
        // spelling expected by the conservative PowerShell evaluator. Do not
        // retain the submitted script body in event metadata.
        var behavioralTag = MapBehavioralIndicator(tag);
        if (!behavioralTag.Equals(tag, StringComparison.Ordinal))
        {
            metadata[IndicatorPrefix + behavioralTag] = "true";
        }

        return new RuntimeSecurityEvent
        {
            Source = RuntimeEventSource.AmsiContentAnalysis,
            Category = RuntimeEventCategory.ScriptObserved,
            Severity = runtimeEvent.Kind == RuntimeTelemetryEventKind.AmsiBypassIndicator
                ? RuntimeEventSeverity.High
                : RuntimeEventSeverity.Medium,
            Title = "AMSI script content observed",
            Description = $"In-memory AMSI telemetry observed script content from '{runtimeEvent.ProcessName}'.",
            ProcessId = runtimeEvent.Pid > 0 ? runtimeEvent.Pid : null,
            ProcessName = runtimeEvent.ProcessName,
            ParentProcessId = runtimeEvent.ParentPid > 0 ? runtimeEvent.ParentPid : null,
            TimestampUtc = runtimeEvent.TimestampUtc == default
                ? DateTimeOffset.UtcNow
                : new DateTimeOffset(runtimeEvent.TimestampUtc.ToUniversalTime()),
            Metadata = metadata,
        };
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { _provider.EventReceived -= OnEventReceived; }
        catch (Exception) { /* teardown is best-effort */ }
    }

    private static string NormalizeIndicator(string value)
        => string.IsNullOrWhiteSpace(value)
            ? "amsi-observation"
            : value.Trim().ToLowerInvariant().Replace('_', '-');

    private static string MapBehavioralIndicator(string tag) => tag switch
    {
        "encoded" or "encoded-payload" => "powershell-encoded-command",
        "dynamic-execution" => "powershell-dynamic-execution",
        "policy-bypass" => "powershell-policy-bypass",
        "hidden-execution" => "powershell-hidden-window",
        _ => tag,
    };

    private void TryDiagnose(string message)
    {
        try { _diagnostics?.Invoke(message); }
        catch (Exception) { /* diagnostics are best-effort */ }
    }
}
