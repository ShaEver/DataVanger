using System;
using System.Collections.Generic;
using System.Threading;
using DataVanger.Memory;
using DataVanger.Shared.RuntimeEvents;

namespace DataVanger.Runtime;

/// <summary>
/// Publishes process-memory findings into the resident runtime-event
/// pipeline used by ETW and the behavioral binding.
///
/// Memory findings are heuristic observations only. This bridge cannot
/// classify malware, request remediation, quarantine, kill, suspend, or
/// block a process.
/// </summary>
public sealed class MemoryRuntimeBridge
{
    private const string IndicatorPrefix = "etw.indicator.";

    private readonly IRuntimeEventPublisher _publisher;
    private readonly Action<string>? _diagnostics;
    private long _published;
    private long _failed;

    public MemoryRuntimeBridge(
        IRuntimeEventPublisher publisher,
        Action<string>? diagnostics = null)
    {
        _publisher = publisher ?? throw new ArgumentNullException(nameof(publisher));
        _diagnostics = diagnostics;
    }

    public long PublishedCount => Interlocked.Read(ref _published);
    public long FailedCount => Interlocked.Read(ref _failed);

    public void Publish(IEnumerable<MemoryFinding>? findings, CancellationToken cancellationToken = default)
    {
        if (findings is null) return;

        foreach (var finding in findings)
        {
            if (finding is null || cancellationToken.IsCancellationRequested) continue;

            try
            {
                _publisher.PublishAsync(Map(finding), cancellationToken).GetAwaiter().GetResult();
                Interlocked.Increment(ref _published);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                Interlocked.Increment(ref _failed);
                return;
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _failed);
                TryDiagnose($"memory-runtime bridge publish failed: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    public static RuntimeSecurityEvent Map(MemoryFinding finding)
    {
        if (finding is null) throw new ArgumentNullException(nameof(finding));

        var indicator = NormalizeIndicator(finding.Kind.ToString());
        var metadata = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [IndicatorPrefix + indicator] = "true",
            ["memory.finding_kind"] = finding.Kind.ToString(),
            ["memory.region_base"] = $"0x{finding.RegionBase:X}",
            ["memory.region_size"] = Math.Max(0, finding.RegionSize).ToString(),
            ["memory.protection"] = finding.Protection.ToString(),
            ["memory.region_kind"] = finding.RegionKind.ToString(),
            ["memory.score_delta"] = Math.Clamp(finding.ScoreDelta, 0, 6).ToString(),
        };

        return new RuntimeSecurityEvent
        {
            Source = RuntimeEventSource.MemoryScanner,
            Category = RuntimeEventCategory.InjectionObserved,
            Severity = MapSeverity(finding.Severity),
            Title = "Process-memory injection indicator observed",
            Description = finding.Description,
            SubjectPath = finding.BackingPath,
            ProcessId = finding.ProcessId,
            ProcessName = finding.ProcessName,
            TimestampUtc = finding.TimestampUtc == default
                ? DateTimeOffset.UtcNow
                : new DateTimeOffset(finding.TimestampUtc.ToUniversalTime()),
            Metadata = metadata,
        };
    }

    private static RuntimeEventSeverity MapSeverity(MemoryScanSeverity severity) => severity switch
    {
        MemoryScanSeverity.High => RuntimeEventSeverity.High,
        MemoryScanSeverity.Medium => RuntimeEventSeverity.Medium,
        MemoryScanSeverity.Low => RuntimeEventSeverity.Low,
        _ => RuntimeEventSeverity.Informational,
    };

    private static string NormalizeIndicator(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "memory-finding";
        return value.Trim().ToLowerInvariant().Replace('_', '-');
    }

    private void TryDiagnose(string message)
    {
        try { _diagnostics?.Invoke(message); }
        catch (Exception) { /* diagnostics are best-effort */ }
    }
}
