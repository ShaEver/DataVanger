using System;
using System.Collections.Generic;
using System.Threading;
using DataVanger.Behavioral;

namespace DataVanger.SelfProtection;

/// <summary>
/// Top-level facade for the Self-Protection subsystem.
///
/// Wires together (lazily, on demand):
///   - the in-memory tamper sink,
///   - the configuration integrity monitor,
///   - the watchdog,
///   - the recovery manager,
///   - an optional bridge to a <see cref="BehavioralEventBus"/>.
///
/// The manager is opt-in: nothing runs until the host constructs an
/// instance. When constructed, every component fails closed — there is
/// no scenario where the manager throws because the host is unsupported
/// or running with reduced privileges.
///
/// Anti-FP contract:
///   - the manager only emits <see cref="TamperEvent"/>s,
///   - tamper events forwarded to the behavioral bus carry
///     <see cref="BehavioralEventKind.SecurityTamperIndicator"/>,
///   - the behavioral rule pipeline ensures the resulting Evidence has
///     <c>CanConfirmMalware = false</c>,
///   - automatic quarantine remains gated by ConfirmedMalware verdicts
///     from the classifier, which the manager cannot produce.
///
/// Development-mode contract:
///   - no filesystem locks are taken,
///   - no background timers/threads/loops are spawned,
///   - the watchdog never invokes recovery callbacks,
///   - tests, dotnet build and bin/obj cleanup are never blocked.
/// </summary>
public sealed class SelfProtectionManager : IDisposable
{
    private readonly SelfProtectionPolicy _policy;
    private readonly InMemoryTamperEventSink _memorySink;
    private readonly CompositeTamperSink _sink;
    private readonly RecoveryManager _recovery;
    private readonly Watchdog _watchdog;
    private ConfigurationIntegrityMonitor? _configMonitor;
    private int _disposed;
    private SelfProtectionState _state = SelfProtectionState.NotStarted;
    private readonly object _stateGate = new();

    public SelfProtectionPolicy Policy => _policy;
    public InMemoryTamperEventSink TamperHistory => _memorySink;
    public ITamperEventSink Sink => _sink;
    public RecoveryManager Recovery => _recovery;
    public Watchdog Watchdog => _watchdog;
    public ConfigurationIntegrityMonitor? ConfigurationMonitor => _configMonitor;
    public SelfProtectionState State { get { lock (_stateGate) return _state; } }

    public SelfProtectionManager(SelfProtectionPolicy? policy = null, BehavioralEngine? behavioral = null)
        : this(policy, behavioral?.Bus)
    {
    }

    public SelfProtectionManager(SelfProtectionPolicy? policy, IBehavioralEventBus? bus)
    {
        _policy = policy ?? SelfProtectionPolicy.DevelopmentDefault();
        _memorySink = new InMemoryTamperEventSink(_policy.TamperHistoryCapacity);
        var sinks = new List<ITamperEventSink> { _memorySink };
        if (bus is not null) sinks.Add(new BehavioralTamperBridge(bus, _policy.Diagnostics));
        _sink = new CompositeTamperSink(sinks, _policy.Diagnostics);
        _recovery = new RecoveryManager(_sink);
        _watchdog = new Watchdog(_policy, _sink);
    }

    /// <summary>
    /// Activate the manager. Idempotent. Returns the post-start state.
    /// When the policy level is <see cref="SelfProtectionLevel.Off"/> the
    /// manager transitions to <see cref="SelfProtectionState.Disabled"/>
    /// and remains a no-op for all subsequent calls.
    /// </summary>
    public SelfProtectionState Start()
    {
        if (Volatile.Read(ref _disposed) == 1) return SelfProtectionState.Stopped;
        lock (_stateGate)
        {
            if (_state == SelfProtectionState.Disabled
                || _state == SelfProtectionState.Active
                || _state == SelfProtectionState.DevelopmentMode
                || _state == SelfProtectionState.Degraded
                || _state == SelfProtectionState.Stopped)
                return _state;

            if (_policy.Level == SelfProtectionLevel.Off)
            {
                _state = SelfProtectionState.Disabled;
                return _state;
            }

            _state = _policy.Mode == SelfProtectionMode.Development
                ? SelfProtectionState.DevelopmentMode
                : SelfProtectionState.Active;
            return _state;
        }
    }

    /// <summary>
    /// Configure the integrity monitor for protected configuration files.
    /// Safe to call multiple times — replaces the previous monitor.
    /// </summary>
    public ConfigurationIntegrityMonitor ConfigureConfigurationMonitor(
        IntegritySnapshot baseline,
        string component = "configuration")
    {
        var monitor = new ConfigurationIntegrityMonitor(baseline, _sink, component: component);
        _configMonitor = monitor;
        return monitor;
    }

    /// <summary>
    /// Convenience: signal that a monitored runtime component reported a
    /// stop attempt. The manager emits a tamper event but never
    /// retaliates — recovery (if any) is the caller's responsibility.
    /// </summary>
    public void ReportServiceStopAttempt(string component, string description, DateTime? nowUtc = null)
    {
        if (!IsActive()) return;
        _sink.Publish(new TamperEvent(
            TamperKind.ServiceStopAttempt,
            TamperSeverity.Medium,
            component ?? "",
            "",
            description ?? "",
            nowUtc?.ToUniversalTime() ?? DateTime.UtcNow));
    }

    /// <summary>
    /// Signal that runtime telemetry has unexpectedly stopped emitting
    /// events. Used by the runtime layer when ETW/AMSI providers go
    /// quiet for longer than the operational SLA.
    /// </summary>
    public void ReportTelemetryInterruption(string component, string description, DateTime? nowUtc = null)
    {
        if (!IsActive()) return;
        _sink.Publish(new TamperEvent(
            TamperKind.TelemetryInterruption,
            TamperSeverity.Medium,
            component ?? "",
            "",
            description ?? "",
            nowUtc?.ToUniversalTime() ?? DateTime.UtcNow));
    }

    private bool IsActive()
    {
        if (Volatile.Read(ref _disposed) == 1) return false;
        lock (_stateGate)
        {
            return _state == SelfProtectionState.Active
                || _state == SelfProtectionState.DevelopmentMode
                || _state == SelfProtectionState.Degraded;
        }
    }

    public void Stop()
    {
        lock (_stateGate)
        {
            if (_state == SelfProtectionState.Stopped) return;
            _state = SelfProtectionState.Stopped;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        Stop();
        try { _memorySink.Dispose(); } catch (Exception) { /* Dispose may throw on already-disposed or never-started instances - ignore. */ }
    }
}
