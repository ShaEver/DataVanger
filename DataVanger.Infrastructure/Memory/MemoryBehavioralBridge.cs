using System;
using System.Collections.Generic;
using DataVanger.Behavioral;

namespace DataVanger.Memory;

/// <summary>
/// Publishes memory findings onto the behavioral event bus so the
/// existing behavioral rule + correlation pipeline can react to them
/// (e.g. combine with an InjectionIndicator emitted by ETW).
///
/// We deliberately map memory findings onto
/// <see cref="BehavioralEventKind.InjectionIndicator"/> with severity
/// derived from the finding — but we never raise behavioral severity
/// above High and never emit a confirmed event. The behavioral engine
/// re-applies its own clamps on top.
/// </summary>
public sealed class MemoryBehavioralBridge
{
    private readonly IBehavioralEventBus _bus;
    private readonly Action<string>? _diagnostics;
    private long _publishedCount;

    public MemoryBehavioralBridge(IBehavioralEventBus bus, Action<string>? diagnostics = null)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _diagnostics = diagnostics;
    }

    public long PublishedCount => System.Threading.Interlocked.Read(ref _publishedCount);

    public void Publish(IEnumerable<MemoryFinding> findings)
    {
        if (findings is null) return;
        foreach (var f in findings)
        {
            if (f is null) continue;
            try
            {
                _bus.Publish(new BehavioralEvent(
                    kind: BehavioralEventKind.InjectionIndicator,
                    pid: f.ProcessId,
                    parentPid: 0,
                    processName: f.ProcessName,
                    imagePath: f.BackingPath,
                    commandLine: "",
                    targetPath: $"0x{f.RegionBase:X}",
                    extraTag: f.Kind.ToString(),
                    severity: MapSeverity(f.Severity),
                    description: f.Description,
                    timestampUtc: f.TimestampUtc));
                System.Threading.Interlocked.Increment(ref _publishedCount);
            }
            catch (Exception ex)
            {
                _diagnostics?.Invoke($"memory-bridge: publish failed: {ex.GetType().Name}");
            }
        }
    }

    private static BehavioralSeverity MapSeverity(MemoryScanSeverity s) => s switch
    {
        MemoryScanSeverity.High => BehavioralSeverity.High,
        MemoryScanSeverity.Medium => BehavioralSeverity.Medium,
        MemoryScanSeverity.Low => BehavioralSeverity.Low,
        _ => BehavioralSeverity.Info,
    };
}
