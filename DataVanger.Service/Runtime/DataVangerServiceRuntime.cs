using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Infrastructure.Etw;
using DataVanger.Service.RuntimeEvents;
using DataVanger.Shared.Etw;
using DataVanger.Shared.RuntimeEvents;
using DataVanger.Shared.Service;

namespace DataVanger.Service.Runtime;

/// <summary>
/// Default DataVanger service runtime introduced in Phase 2 Step 02
/// (Windows Service Host).
///
/// Behavior:
///   - StartAsync / StopAsync are idempotent and safe under any order.
///   - All registered protection modules are Passive / NotImplemented /
///     Disabled — never reported as active protection.
///   - The runtime does NOT spin up background threads, watchdog loops,
///     timers, file watchers, AMSI providers, IPC channels, or network
///     listeners. It stays fully passive UNLESS
///     <see cref="DataVangerServiceConfiguration.EnableEtwRuntimeTelemetry"/>
///     is explicitly set: then, in Service mode on a supported/privileged
///     Windows host, it starts the existing bounded, gated
///     <see cref="WindowsEtwRuntimeProvider"/> via <see cref="EtwRuntimeProviderHost"/>
///     and publishes process telemetry into a bounded in-process pipeline.
///     That telemetry is heuristic-only, never confirms malware, performs no
///     blocking/quarantine, and degrades to Null on any failure without crashing.
///   - Configuration load failures degrade gracefully and become
///     warnings on the status snapshot.
///   - Cancellation during startup is honored and leaves the runtime in
///     Stopped state, not Failed.
/// </summary>
public sealed class DataVangerServiceRuntime : IDataVangerServiceRuntime
{
    private readonly object _gate = new();
    private readonly DataVangerServiceConfiguration _configuration;
    private readonly List<string> _warnings = new();
    private readonly DataVangerRuntimeMode _mode;
    private readonly Func<bool>? _etwPlatformProbe;
    private DataVangerServiceState _state = DataVangerServiceState.NotStarted;
    private DateTimeOffset? _startedAtUtc;
    private DateTimeOffset _lastUpdatedUtc = DateTimeOffset.UtcNow;
    private bool _disposed;

    // Real ETW runtime telemetry (opt-in via configuration). Null unless
    // EnableEtwRuntimeTelemetry is set and the provider was selected.
    private IEtwRuntimeProvider? _etwProvider;
    private IRuntimeEventPipeline? _runtimeEventPipeline;
    private EtwProviderStatus _etwStatus = EtwProviderStatus.Disabled;
    private string? _etwLastError;

    public DataVangerServiceRuntime()
        : this(DataVangerServiceConfiguration.SafeDefaults(), DataVangerRuntimeMode.Development, Array.Empty<string>())
    {
    }

    public DataVangerServiceRuntime(
        DataVangerServiceConfiguration configuration,
        DataVangerRuntimeMode mode,
        IReadOnlyList<string>? configWarnings = null,
        Func<bool>? etwPlatformProbe = null)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _mode = configuration.ForceDevelopmentMode ? DataVangerRuntimeMode.Development : mode;
        // Test-only seam: lets automated tests force the ETW platform gate so a
        // real Windows ETW session is NEVER opened during unit tests. In
        // production this is null and collapses to OperatingSystem.IsWindows().
        _etwPlatformProbe = etwPlatformProbe;
        if (configWarnings is { Count: > 0 })
        {
            _warnings.AddRange(configWarnings);
        }
    }

    public DataVangerRuntimeMode Mode => _mode;

    public DataVangerServiceState State
    {
        get { lock (_gate) return _state; }
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        bool shouldStartEtw;
        lock (_gate)
        {
            if (_disposed)
            {
                // Disposed runtimes never resurrect — keep the existing terminal state.
                return;
            }

            if (_state == DataVangerServiceState.Running
                || _state == DataVangerServiceState.Degraded
                || _state == DataVangerServiceState.Starting)
            {
                // Idempotent: already running / starting — no duplicate activation.
                return;
            }

            if (cancellationToken.IsCancellationRequested)
            {
                // Honor cancellation before any side effect.
                _state = DataVangerServiceState.Stopped;
                _lastUpdatedUtc = DateTimeOffset.UtcNow;
                throw new OperationCanceledException(cancellationToken);
            }

            _state = DataVangerServiceState.Starting;
            _startedAtUtc = DateTimeOffset.UtcNow;
            _lastUpdatedUtc = _startedAtUtc.Value;

            // The transition to Running (or Degraded) is state-machine bookkeeping.
            // The ONLY optional background work is the opt-in ETW telemetry provider
            // below — started after the lock and fully fail-closed.
            if (!_configuration.ServiceEnabled)
            {
                _warnings.Add("ServiceEnabled=false in configuration; runtime started in Degraded passive mode.");
                _state = DataVangerServiceState.Degraded;
            }
            else
            {
                _state = DataVangerServiceState.Running;
            }

            _lastUpdatedUtc = DateTimeOffset.UtcNow;
            shouldStartEtw = _state == DataVangerServiceState.Running
                && _configuration.EnableEtwRuntimeTelemetry;
        }

        if (shouldStartEtw)
        {
            // Outside the lock (async). Never throws: degrades to a warning.
            await StartEtwRuntimeTelemetryAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Opt-in activation of the existing, already-gated and bounded ETW runtime
    /// provider. Selection goes through <see cref="EtwProviderFactory.Create"/>
    /// (via <see cref="EtwRuntimeProviderHost"/>): non-Windows, unprivileged, or
    /// development-mode hosts receive the Null provider, so this method opens a
    /// real ETW session ONLY on a privileged Windows Service host. Every failure
    /// path degrades to a warning; the runtime keeps running. Telemetry is
    /// published into a bounded in-process pipeline and is heuristic-only.
    /// </summary>
    private async Task StartEtwRuntimeTelemetryAsync(CancellationToken cancellationToken)
    {
        IRuntimeEventPipeline? pipeline = null;
        IEtwRuntimeProvider? provider = null;
        try
        {
            var etwConfig = new EtwProviderConfiguration
            {
                Enabled = true,
                AllowRealProvider = true,
                // Real Windows capture only in genuine Service mode; Development/
                // Console keep DevelopmentMode=true so the factory returns Null.
                DevelopmentMode = _mode != DataVangerRuntimeMode.Service,
                CaptureProcessStart = true,
                CaptureCommandLine = false,
                CapturePowerShellSignals = false,
                SanitizeCommandLines = true,
            }.WithSafeDefaults();

            pipeline = RuntimeEventPipelineFactory.CreateDevelopmentPipeline();
            provider = EtwRuntimeProviderHost.CreateProvider(pipeline, etwConfig, _etwPlatformProbe);
            var status = await EtwRuntimeProviderHost.SafeStartAsync(provider, cancellationToken).ConfigureAwait(false);

            // Preserve the provider's own last-error (the exact exception type+message
            // captured during real-session activation) so a degraded status such as
            // ProviderUnavailable is never opaque. GetHealth() never throws by contract.
            string? lastError = null;
            try { lastError = provider.GetHealth().LastError; }
            catch (Exception) { /* health probe must never throw back */ }

            lock (_gate)
            {
                if (!_disposed)
                {
                    _runtimeEventPipeline = pipeline;
                    _etwProvider = provider;
                    _etwStatus = status;
                    _etwLastError = lastError;
                    if (status != EtwProviderStatus.Running)
                    {
                        var detail = string.IsNullOrWhiteSpace(lastError) ? string.Empty : $" (last error: {lastError})";
                        _warnings.Add($"ETW runtime telemetry enabled but provider status is '{status}'{detail}; runtime continues without real ETW (safe fallback).");
                    }
                    _lastUpdatedUtc = DateTimeOffset.UtcNow;
                    pipeline = null; // ownership transferred to the runtime
                    provider = null;
                }
            }
        }
        catch (Exception ex)
        {
            lock (_gate)
            {
                _etwStatus = EtwProviderStatus.Faulted;
                _etwLastError = $"{ex.GetType().Name}: {ex.Message}";
                _warnings.Add($"ETW runtime telemetry failed to start ({ex.GetType().Name}: {ex.Message}); runtime continues without it.");
                _lastUpdatedUtc = DateTimeOffset.UtcNow;
            }
        }
        finally
        {
            // Created but not retained (disposed mid-start, or an exception
            // occurred): tear down so nothing leaks.
            if (provider is not null)
                await EtwRuntimeProviderHost.SafeStopAsync(provider, CancellationToken.None).ConfigureAwait(false);
            if (pipeline is not null)
            {
                try { pipeline.Dispose(); } catch (Exception) { /* teardown is best-effort */ }
            }
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        IEtwRuntimeProvider? provider;
        IRuntimeEventPipeline? pipeline;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            // Detach any ETW provider/pipeline so teardown happens once, outside the lock.
            provider = _etwProvider;
            pipeline = _runtimeEventPipeline;
            _etwProvider = null;
            _runtimeEventPipeline = null;

            if (_state == DataVangerServiceState.NotStarted
                || _state == DataVangerServiceState.Stopped
                || _state == DataVangerServiceState.Stopping)
            {
                // Idempotent: Stop-before-Start and double-Stop are no-ops.
                _state = DataVangerServiceState.Stopped;
                _lastUpdatedUtc = DateTimeOffset.UtcNow;
            }
            else
            {
                _state = DataVangerServiceState.Stopping;
                _lastUpdatedUtc = DateTimeOffset.UtcNow;
                _state = DataVangerServiceState.Stopped;
                _lastUpdatedUtc = DateTimeOffset.UtcNow;
            }

            if (provider is not null) _etwStatus = EtwProviderStatus.Stopped;
        }

        // Graceful, fail-closed teardown of optional ETW telemetry (no-op when absent).
        if (provider is not null)
            await EtwRuntimeProviderHost.SafeStopAsync(provider, cancellationToken).ConfigureAwait(false);
        if (pipeline is not null)
        {
            try { pipeline.Dispose(); } catch (Exception) { /* teardown is best-effort */ }
        }
    }

    public DataVangerServiceStatus GetStatusSnapshot()
    {
        lock (_gate)
        {
            var modules = BuildModuleSnapshot();
            var warnings = _warnings.Count == 0
                ? Array.Empty<string>()
                : _warnings.ToArray();

            return new DataVangerServiceStatus(
                state: _state,
                mode: _mode,
                lastUpdatedUtc: _lastUpdatedUtc,
                startedAtUtc: _startedAtUtc,
                warnings: warnings,
                modules: modules);
        }
    }

    private DataVangerRuntimeModuleStatus[] BuildModuleSnapshot()
    {
        // Honest passive registration: every protection-oriented module
        // ships in Phase 2 Step 02 as a placeholder. Anti-FP policy
        // requires they NEVER be reported as active protection.
        return new[]
        {
            new DataVangerRuntimeModuleStatus(
                "EngineComposition",
                RuntimeModuleAvailability.Passive,
                "Engine composition surface reserved; on-demand scanning remains via the UI."),
            new DataVangerRuntimeModuleStatus(
                "ScannerEngine",
                RuntimeModuleAvailability.Passive,
                "On-demand scan engine is owned by the UI process in this phase."),
            new DataVangerRuntimeModuleStatus(
                "Configuration",
                _warnings.Count == 0
                    ? RuntimeModuleAvailability.Available
                    : RuntimeModuleAvailability.Degraded,
                _warnings.Count == 0
                    ? "Configuration loaded (or safe defaults applied)."
                    : "Configuration loaded with warnings; safe defaults in effect for any missing fields."),
            new DataVangerRuntimeModuleStatus(
                "Quarantine",
                RuntimeModuleAvailability.Passive,
                "Quarantine remains UI-driven; no automatic quarantine from runtime events."),
            new DataVangerRuntimeModuleStatus(
                "Scheduler",
                RuntimeModuleAvailability.Passive,
                "Scheduler remains UI-driven; no resident scheduling loop in the service."),
            new DataVangerRuntimeModuleStatus(
                "SelfProtection",
                RuntimeModuleAvailability.Passive,
                "Self-protection development-safe defaults preserved; no resident watchdog."),
            new DataVangerRuntimeModuleStatus(
                "RealtimeProtectionPlaceholder",
                RuntimeModuleAvailability.NotImplemented,
                "Realtime file blocking / AMSI registration is deferred to a future phase."),
            BuildRuntimeTelemetryModule(),
        };
    }

    /// <summary>
    /// Reports the runtime-telemetry module honestly. When ETW telemetry is NOT
    /// enabled (the default), it remains the NotImplemented placeholder exactly
    /// as before. When enabled, it surfaces the real provider's status as a
    /// <see cref="RuntimeModuleAvailability.Passive"/> module when running —
    /// never <see cref="RuntimeModuleAvailability.Available"/>, because telemetry
    /// is passive/heuristic-only and must never count as active protection — and
    /// <see cref="RuntimeModuleAvailability.Degraded"/> when unavailable.
    /// </summary>
    private DataVangerRuntimeModuleStatus BuildRuntimeTelemetryModule()
    {
        if (!_configuration.EnableEtwRuntimeTelemetry)
        {
            return new DataVangerRuntimeModuleStatus(
                "RuntimeTelemetryPlaceholder",
                RuntimeModuleAvailability.NotImplemented,
                "Runtime telemetry resident pipeline is deferred to a future phase.");
        }

        return _etwStatus == EtwProviderStatus.Running
            ? new DataVangerRuntimeModuleStatus(
                "RuntimeTelemetry",
                RuntimeModuleAvailability.Passive,
                "Real ETW process telemetry active (Windows): passive, bounded, heuristic-only; never confirms malware; performs no blocking or quarantine.")
            : new DataVangerRuntimeModuleStatus(
                "RuntimeTelemetry",
                RuntimeModuleAvailability.Degraded,
                string.IsNullOrWhiteSpace(_etwLastError)
                    ? $"ETW runtime telemetry enabled but provider status is '{_etwStatus}'; degraded to safe fallback. No active protection."
                    : $"ETW runtime telemetry enabled but provider status is '{_etwStatus}' (last error: {_etwLastError}); degraded to safe fallback. No active protection.");
    }

    public void Dispose()
    {
        IEtwRuntimeProvider? provider;
        IRuntimeEventPipeline? pipeline;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            provider = _etwProvider;
            pipeline = _runtimeEventPipeline;
            _etwProvider = null;
            _runtimeEventPipeline = null;
            if (_state != DataVangerServiceState.Stopped
                && _state != DataVangerServiceState.NotStarted)
            {
                _state = DataVangerServiceState.Stopped;
                _lastUpdatedUtc = DateTimeOffset.UtcNow;
            }
        }

        // Best-effort, fail-closed teardown of any opt-in ETW telemetry.
        if (provider is not null)
        {
            try { EtwRuntimeProviderHost.SafeStopAsync(provider, CancellationToken.None).GetAwaiter().GetResult(); }
            catch (Exception) { /* Dispose never throws */ }
        }
        if (pipeline is not null)
        {
            try { pipeline.Dispose(); } catch (Exception) { /* Dispose never throws */ }
        }
    }
}
