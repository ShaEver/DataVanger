using System;
using DataVanger.Behavioral;

namespace DataVanger.SelfProtection;

/// <summary>
/// Forwards <see cref="TamperEvent"/>s onto a
/// <see cref="IBehavioralEventBus"/> as
/// <see cref="BehavioralEventKind.SecurityTamperIndicator"/> events.
///
/// The bridge is the ONLY path by which self-protection observations
/// influence the behavioral correlation chain. It deliberately:
///
///   - publishes with severity that never exceeds
///     <see cref="BehavioralSeverity.High"/>,
///   - leaves <c>BehavioralEvent.Pid</c> at zero (the manager has no
///     trusted attacker process to attribute the event to),
///   - tags events with <c>"self-protection"</c> so behavioral rules can
///     recognise the origin if they want to.
///
/// Behavioral rules (e.g. <see cref="DataVanger.Behavioral.Rules.SecurityTamperRule"/>)
/// will, in turn, emit Evidence with <c>CanConfirmMalware = false</c>.
/// This preserves the anti-FP contract: self-protection telemetry alone
/// is NEVER ConfirmedMalware.
/// </summary>
public sealed class BehavioralTamperBridge : ITamperEventSink
{
    private readonly IBehavioralEventBus _bus;
    private readonly Action<string>? _diagnostics;
    private long _forwarded;
    private long _dropped;

    public long ForwardedCount => System.Threading.Interlocked.Read(ref _forwarded);
    public long DroppedCount => System.Threading.Interlocked.Read(ref _dropped);

    public BehavioralTamperBridge(IBehavioralEventBus bus, Action<string>? diagnostics = null)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _diagnostics = diagnostics;
    }

    public bool Publish(TamperEvent ev)
    {
        if (ev is null) { System.Threading.Interlocked.Increment(ref _dropped); return false; }

        try
        {
            var behavioral = new BehavioralEvent(
                kind: BehavioralEventKind.SecurityTamperIndicator,
                pid: 0,
                parentPid: 0,
                processName: "",
                imagePath: "",
                commandLine: "",
                targetPath: ev.TargetPath,
                extraTag: "self-protection",
                severity: MapSeverity(ev.Severity),
                description: BuildDescription(ev),
                timestampUtc: ev.TimestampUtc);
            bool published = _bus.Publish(behavioral);
            if (published) System.Threading.Interlocked.Increment(ref _forwarded);
            else System.Threading.Interlocked.Increment(ref _dropped);
            return published;
        }
        catch (Exception ex)
        {
            System.Threading.Interlocked.Increment(ref _dropped);
            try { _diagnostics?.Invoke($"behavioral tamper bridge error: {ex.GetType().Name}: {ex.Message}"); } catch (Exception) { /* Diagnostics sink must never throw back to callers - swallow intentionally. */ }
            return false;
        }
    }

    private static BehavioralSeverity MapSeverity(TamperSeverity severity) => severity switch
    {
        TamperSeverity.High => BehavioralSeverity.High,
        TamperSeverity.Medium => BehavioralSeverity.Medium,
        TamperSeverity.Low => BehavioralSeverity.Low,
        _ => BehavioralSeverity.Info,
    };

    private static string BuildDescription(TamperEvent ev)
    {
        string target = string.IsNullOrEmpty(ev.TargetPath) ? "" : $" [{ev.TargetPath}]";
        return $"Self-protection: {ev.Kind} ({ev.Component}){target}: {ev.Description}";
    }
}
