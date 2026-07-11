using System;
using System.Threading;
using DataVanger.Behavioral;
using DataVanger.Runtime.Amsi;
using DataVanger.Runtime.Etw;

namespace DataVanger.Runtime;

/// <summary>
/// Translates <see cref="RuntimeTelemetryEvent"/>s coming from ETW/AMSI
/// providers into <see cref="BehavioralEvent"/>s on the behavioral bus.
///
/// Responsibilities:
///   - subscribe to one or more providers,
///   - apply a <see cref="RuntimeTelemetryThrottle"/> per kind/pid,
///   - map provider events to the right behavioral event kind,
///   - never panic when a provider fires an unexpected payload.
///
/// The bridge intentionally does NOT make malware decisions. It
/// converts kinds, tags and timestamps; everything else is the rule
/// engine's job. Every emitted behavioral event has Severity <= High
/// and goes through the normal rule pipeline which enforces the
/// project-wide anti-FP contract.
/// </summary>
public sealed class RuntimeTelemetryBridge : IDisposable
{
    private readonly IBehavioralEventBus _bus;
    private readonly RuntimeTelemetryThrottle _throttle;
    private readonly Action<string>? _diagnostics;
    private readonly object _subLock = new();
    private Action<RuntimeTelemetryEvent>? _etwHandler;
    private Action<RuntimeTelemetryEvent>? _amsiHandler;
    private IEtwTelemetryProvider? _etw;
    private IAmsiTelemetryProvider? _amsi;
    private long _published;
    private long _droppedByThrottle;
    private long _droppedByBus;
    private int _disposed;

    public long PublishedCount => Interlocked.Read(ref _published);
    public long DroppedByThrottleCount => Interlocked.Read(ref _droppedByThrottle);
    public long DroppedByBusCount => Interlocked.Read(ref _droppedByBus);
    public RuntimeTelemetryThrottle Throttle => _throttle;

    public RuntimeTelemetryBridge(
        IBehavioralEventBus bus,
        RuntimeTelemetryThrottle? throttle = null,
        Action<string>? diagnostics = null)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _throttle = throttle ?? new RuntimeTelemetryThrottle();
        _diagnostics = diagnostics;
    }

    /// <summary>Attach an ETW provider. Replaces any previous one.</summary>
    public void AttachEtw(IEtwTelemetryProvider? provider)
    {
        lock (_subLock)
        {
            DetachEtwLocked();
            if (provider is null) return;
            _etw = provider;
            _etwHandler = OnRuntimeEvent;
            _etw.EventReceived += _etwHandler;
        }
    }

    /// <summary>Attach an AMSI provider. Replaces any previous one.</summary>
    public void AttachAmsi(IAmsiTelemetryProvider? provider)
    {
        lock (_subLock)
        {
            DetachAmsiLocked();
            if (provider is null) return;
            _amsi = provider;
            _amsiHandler = OnRuntimeEvent;
            _amsi.EventReceived += _amsiHandler;
        }
    }

    private void DetachEtwLocked()
    {
        if (_etw is not null && _etwHandler is not null)
        {
            try { _etw.EventReceived -= _etwHandler; } catch (Exception) { /* Event unsubscription during teardown may throw on disposed instances - ignore. */ }
        }
        _etw = null;
        _etwHandler = null;
    }

    private void DetachAmsiLocked()
    {
        if (_amsi is not null && _amsiHandler is not null)
        {
            try { _amsi.EventReceived -= _amsiHandler; } catch (Exception) { /* Event unsubscription during teardown may throw on disposed instances - ignore. */ }
        }
        _amsi = null;
        _amsiHandler = null;
    }

    private void OnRuntimeEvent(RuntimeTelemetryEvent ev)
    {
        if (ev is null) return;
        if (Volatile.Read(ref _disposed) == 1) return;
        try
        {
            if (!_throttle.ShouldAllow(ev))
            {
                Interlocked.Increment(ref _droppedByThrottle);
                return;
            }
            var behavioral = Translate(ev);
            if (behavioral is null) return;
            bool accepted = _bus.Publish(behavioral);
            if (!accepted) Interlocked.Increment(ref _droppedByBus);
            else Interlocked.Increment(ref _published);
        }
        catch (Exception ex)
        {
            try { _diagnostics?.Invoke($"runtime bridge error: {ex.GetType().Name}: {ex.Message}"); } catch (Exception) { /* Diagnostics sink must never throw back to callers - swallow intentionally. */ }
        }
    }

    /// <summary>
    /// Map a <see cref="RuntimeTelemetryEvent"/> to its behavioral kind +
    /// severity. <c>null</c> means "ignore this event silently".
    /// </summary>
    public static BehavioralEvent? Translate(RuntimeTelemetryEvent ev)
    {
        if (ev is null) return null;
        BehavioralEventKind kind;
        BehavioralSeverity sev = BehavioralSeverity.Info;
        string desc;

        switch (ev.Kind)
        {
            case RuntimeTelemetryEventKind.ProcessStart:
                kind = BehavioralEventKind.ProcessStart;
                desc = $"Processo iniciado: {ev.ProcessName}";
                break;
            case RuntimeTelemetryEventKind.ProcessEnd:
                kind = BehavioralEventKind.ProcessEnd;
                desc = $"Processo terminado: {ev.ProcessName}";
                break;
            case RuntimeTelemetryEventKind.ImageLoad:
                kind = BehavioralEventKind.ProcessStart; // backfill ancestry; rules don't fire on this alone
                desc = $"Imagem carregada: {ev.ImagePath}";
                break;
            case RuntimeTelemetryEventKind.ScriptExecution:
                kind = BehavioralEventKind.ScriptExecution;
                sev  = BehavioralSeverity.Low;
                desc = $"Execução de script via {ev.ProviderName}";
                break;
            case RuntimeTelemetryEventKind.AmsiScan:
                // AmsiScan is a "we saw script content" signal. It maps to
                // ScriptExecution so the EncodedPowerShellRule can pick up
                // tags carried by the runtime event (encoded, dynamic, ...).
                kind = BehavioralEventKind.ScriptExecution;
                sev  = ev.ExtraTag.Equals("security-tamper", StringComparison.OrdinalIgnoreCase)
                    ? BehavioralSeverity.High : BehavioralSeverity.Medium;
                desc = $"Conteúdo de script visto via AMSI ({ev.ExtraTag})";
                break;
            case RuntimeTelemetryEventKind.AmsiBypassIndicator:
                kind = BehavioralEventKind.AmsiBypassIndicator;
                sev  = BehavioralSeverity.High;
                desc = "Indicador de bypass AMSI no conteúdo de script";
                break;
            case RuntimeTelemetryEventKind.SecurityRelevant:
                kind = BehavioralEventKind.SecurityTamperIndicator;
                sev  = BehavioralSeverity.High;
                desc = $"Telemetria de segurança relevante: {ev.ExtraTag}";
                break;
            default:
                return null;
        }

        // Pass the script content along on AMSI events so downstream rules
        // that match on command-line patterns can still see it. We deliberately
        // route the script body through the CommandLine field — the analyzer
        // is content-shape agnostic and rules already expect to look there.
        string commandLine = string.IsNullOrEmpty(ev.CommandLine)
            ? ev.ScriptContent
            : ev.CommandLine;

        return new BehavioralEvent(
            kind: kind,
            pid: ev.Pid,
            parentPid: ev.ParentPid,
            processName: ev.ProcessName,
            imagePath: ev.ImagePath,
            commandLine: commandLine,
            targetPath: "",
            extraTag: ev.ExtraTag,
            severity: sev,
            description: desc,
            timestampUtc: ev.TimestampUtc);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        lock (_subLock)
        {
            DetachEtwLocked();
            DetachAmsiLocked();
        }
    }
}
