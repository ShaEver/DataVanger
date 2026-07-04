using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Behavioral.Runtime;
using DataVanger.Infrastructure.Etw;
using DataVanger.Memory;
using DataVanger.Runtime;
using DataVanger.Runtime.Amsi;
using DataVanger.Service.Behavioral;
using DataVanger.Service.RuntimeEvents;
using DataVanger.Shared.Behavioral.Runtime;
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
    private readonly IMemoryScanner _memoryScanner;
    private readonly MemoryScannerOptions _memoryScannerOptions;
    private readonly Func<IAmsiTelemetryProvider> _amsiProviderFactory;
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

    // One-shot/sob-demanda process-memory telemetry. The startup pass is
    // opt-in and bounded by MemoryScannerOptions; no timer or loop exists.
    private MemoryRuntimeBridge? _memoryBridge;
    private MemoryScanResult? _memoryScanResult;
    private bool _memoryPassAttempted;
    private string? _memoryLastError;

    // In-memory AMSI content observation. This provider has no background
    // capture: it emits only when SubmitAmsiContent is explicitly called.
    private IAmsiTelemetryProvider? _amsiProvider;
    private AmsiRuntimeBridge? _amsiBridge;
    private RuntimeProviderState _amsiState = RuntimeProviderState.NotStarted;
    private string? _amsiLastError;
    private string? _amsiProviderName;

    // Behavioral runtime correlation (opt-in). Bound to the SAME runtime-event
    // pipeline the ETW provider publishes into, so real process telemetry is
    // correlated into evidence-only behavioral signals. Passive/heuristic-only;
    // never confirms malware, never acts. Null unless ETW telemetry is enabled
    // and the binding was selected.
    private BehavioralRuntimeBinding? _behavioralBinding;
    private BehavioralRuntimeBindingState _behavioralState = BehavioralRuntimeBindingState.Disabled;

    public DataVangerServiceRuntime()
        : this(DataVangerServiceConfiguration.SafeDefaults(), DataVangerRuntimeMode.Development, Array.Empty<string>())
    {
    }

    public DataVangerServiceRuntime(
        DataVangerServiceConfiguration configuration,
        DataVangerRuntimeMode mode,
        IReadOnlyList<string>? configWarnings = null,
        Func<bool>? etwPlatformProbe = null,
        IMemoryScanner? memoryScanner = null,
        MemoryScannerOptions? memoryScannerOptions = null,
        Func<IAmsiTelemetryProvider>? amsiProviderFactory = null)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _mode = configuration.ForceDevelopmentMode ? DataVangerRuntimeMode.Development : mode;
        // Test-only seam: lets automated tests force the ETW platform gate so a
        // real Windows ETW session is NEVER opened during unit tests. In
        // production this is null and collapses to OperatingSystem.IsWindows().
        _etwPlatformProbe = etwPlatformProbe;
        _memoryScanner = memoryScanner ?? MemoryScannerFactory.CreateSafeDefault(AddWarning);
        _memoryScannerOptions = CreateBoundedMemoryOptions(memoryScannerOptions);
        // A single AMSI provider is ever created here, so the real ingest
        // provider and the in-memory provider are mutually exclusive and events
        // are never duplicated. The real provider is selected ONLY when it is
        // opted in AND the runtime is a genuine Windows service; it degrades to
        // the in-memory analyzer everywhere else.
        _amsiProviderFactory = amsiProviderFactory ?? CreateConfiguredAmsiProvider;
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
        bool shouldStartResidentRuntime;
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
            shouldStartResidentRuntime = _state == DataVangerServiceState.Running;
        }

        if (shouldStartResidentRuntime)
        {
            // Outside the lock. Every producer is passive and fail-closed.
            await StartResidentRuntimeAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Creates one bounded in-process pipeline shared by the behavioral
    /// consumer and every resident producer. ETW remains opt-in; the memory
    /// pass remains opt-in and runs exactly once here; AMSI is an inert
    /// in-memory observer until content is explicitly submitted.
    /// </summary>
    private async Task StartResidentRuntimeAsync(CancellationToken cancellationToken)
    {
        IRuntimeEventPipeline? pipeline = null;
        IEtwRuntimeProvider? etwProvider = null;
        BehavioralRuntimeBinding? binding = null;
        IAmsiTelemetryProvider? amsiProvider = null;
        AmsiRuntimeBridge? amsiBridge = null;
        MemoryRuntimeBridge? memoryBridge = null;

        var etwStatus = EtwProviderStatus.Disabled;
        string? etwLastError = null;
        var amsiState = RuntimeProviderState.NotStarted;
        string? amsiLastError = null;
        string? amsiProviderName = null;
        MemoryScanResult? memoryResult = null;
        string? memoryLastError = null;
        bool memoryPassAttempted = false;

        try
        {
            pipeline = RuntimeEventPipelineFactory.CreateDevelopmentPipeline();

            // Subscribe the passive behavioral consumer before any producer
            // emits, so startup memory findings and submitted AMSI content use
            // the same correlation path as ETW.
            binding = BehavioralRuntimeBindingFactory.Create(
                _mode == DataVangerRuntimeMode.Service
                    ? BehavioralRuntimeBindingOptions.Passive()
                    : BehavioralRuntimeBindingOptions.DevelopmentSafe(),
                pipeline);
            try
            {
                await binding.StartAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                AddWarning($"Behavioral runtime binding failed to start ({ex.GetType().Name}: {ex.Message}); resident telemetry continues without correlation.");
                try { binding.Dispose(); } catch (Exception) { /* best-effort teardown */ }
                binding = null;
            }

            if (_configuration.EnableEtwRuntimeTelemetry)
            {
                try
                {
                    var etwConfig = new EtwProviderConfiguration
                    {
                        Enabled = true,
                        AllowRealProvider = true,
                        // Real capture only in genuine Service mode.
                        DevelopmentMode = _mode != DataVangerRuntimeMode.Service,
                        CaptureProcessStart = true,
                        CaptureCommandLine = _configuration.CaptureEtwCommandLine,
                        CapturePowerShellSignals = _configuration.CaptureEtwPowerShellSignals,
                        SanitizeCommandLines = true,
                    }.WithSafeDefaults();

                    etwProvider = EtwRuntimeProviderHost.CreateProvider(
                        pipeline, etwConfig, _etwPlatformProbe);
                    etwStatus = await EtwRuntimeProviderHost
                        .SafeStartAsync(etwProvider, cancellationToken)
                        .ConfigureAwait(false);

                    try { etwLastError = etwProvider.GetHealth().LastError; }
                    catch (Exception) { /* health probes are best-effort */ }

                    if (etwStatus != EtwProviderStatus.Running)
                    {
                        var detail = string.IsNullOrWhiteSpace(etwLastError)
                            ? string.Empty
                            : $" (last error: {etwLastError})";
                        AddWarning($"ETW runtime telemetry enabled but provider status is '{etwStatus}'{detail}; runtime continues without real ETW (safe fallback).");
                    }
                }
                catch (Exception ex)
                {
                    etwStatus = EtwProviderStatus.Faulted;
                    etwLastError = $"{ex.GetType().Name}: {ex.Message}";
                    AddWarning($"ETW runtime telemetry failed to start ({etwLastError}); runtime continues without it.");
                    if (etwProvider is not null)
                    {
                        await EtwRuntimeProviderHost
                            .SafeStopAsync(etwProvider, CancellationToken.None)
                            .ConfigureAwait(false);
                        etwProvider = null;
                    }
                }
            }

            // The in-memory AMSI provider opens no OS registration/session and
            // creates no background loop. It emits only on SubmitContent.
            try
            {
                amsiProvider = _amsiProviderFactory();
                amsiProviderName = amsiProvider.Name;
                amsiBridge = new AmsiRuntimeBridge(amsiProvider, pipeline, AddWarning);
                amsiState = amsiProvider.Start();
                if (amsiState is not (RuntimeProviderState.Running or RuntimeProviderState.RunningMock))
                {
                    amsiLastError = $"provider state is '{amsiState}'";
                    AddWarning($"AMSI runtime observation degraded: {amsiLastError}.");
                }
            }
            catch (Exception ex)
            {
                amsiState = RuntimeProviderState.Failed;
                amsiLastError = $"{ex.GetType().Name}: {ex.Message}";
                AddWarning($"AMSI runtime observation failed to start ({amsiLastError}); explicit content submission remains unavailable.");
                try { amsiBridge?.Dispose(); } catch (Exception) { /* best-effort */ }
                try { amsiProvider?.Dispose(); } catch (Exception) { /* best-effort */ }
                amsiBridge = null;
                amsiProvider = null;
            }

            memoryBridge = new MemoryRuntimeBridge(pipeline, AddWarning);
            if (_configuration.EnableMemoryScanPass)
            {
                memoryPassAttempted = true;
                try
                {
                    // Deliberately synchronous and one-shot: no Task.Run, no
                    // resident worker, no timer/loop owned by the service.
                    memoryResult = _memoryScanner.Scan(_memoryScannerOptions, cancellationToken);
                    memoryBridge.Publish(memoryResult.Findings, cancellationToken);
                    if (memoryResult.IsDegraded)
                    {
                        memoryLastError = string.IsNullOrWhiteSpace(memoryResult.DegradationDetail)
                            ? memoryResult.Degradation.ToString()
                            : $"{memoryResult.Degradation}: {memoryResult.DegradationDetail}";
                        AddWarning($"Memory runtime pass degraded ({memoryLastError}); service continues without active memory protection.");
                    }
                }
                catch (Exception ex)
                {
                    memoryLastError = $"{ex.GetType().Name}: {ex.Message}";
                    AddWarning($"Memory runtime pass failed ({memoryLastError}); service continues without active memory protection.");
                }
            }

            lock (_gate)
            {
                if (!_disposed)
                {
                    _runtimeEventPipeline = pipeline;
                    _etwProvider = etwProvider;
                    _behavioralBinding = binding;
                    _behavioralState = binding?.GetStatus().State
                        ?? BehavioralRuntimeBindingState.Disabled;
                    _etwStatus = etwStatus;
                    _etwLastError = etwLastError;
                    _amsiProvider = amsiProvider;
                    _amsiBridge = amsiBridge;
                    _amsiState = amsiState;
                    _amsiLastError = amsiLastError;
                    _amsiProviderName = amsiProviderName;
                    _memoryBridge = memoryBridge;
                    _memoryScanResult = memoryResult;
                    _memoryPassAttempted = memoryPassAttempted;
                    _memoryLastError = memoryLastError;
                    _lastUpdatedUtc = DateTimeOffset.UtcNow;

                    pipeline = null;
                    etwProvider = null;
                    binding = null;
                    amsiProvider = null;
                    amsiBridge = null;
                    memoryBridge = null;
                }
            }
        }
        catch (Exception ex)
        {
            AddWarning($"Resident runtime pipeline failed to start ({ex.GetType().Name}: {ex.Message}); service continues in degraded passive mode.");
            lock (_gate)
            {
                _behavioralState = BehavioralRuntimeBindingState.Disabled;
                _lastUpdatedUtc = DateTimeOffset.UtcNow;
            }
        }
        finally
        {
            // Created but not retained (disposed mid-start or fatal pipeline
            // failure): preserve the existing consumer-first teardown pattern,
            // then detach AMSI, stop ETW, and finally dispose the pipeline.
            if (binding is not null)
            {
                try { await binding.StopAsync(CancellationToken.None).ConfigureAwait(false); } catch (Exception) { /* best-effort */ }
                try { binding.Dispose(); } catch (Exception) { /* best-effort */ }
            }
            if (amsiBridge is not null)
            {
                try { amsiBridge.Dispose(); } catch (Exception) { /* best-effort */ }
            }
            if (amsiProvider is not null)
            {
                try { amsiProvider.Stop(); } catch (Exception) { /* best-effort */ }
                try { amsiProvider.Dispose(); } catch (Exception) { /* best-effort */ }
            }
            if (etwProvider is not null)
            {
                await EtwRuntimeProviderHost
                    .SafeStopAsync(etwProvider, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            if (pipeline is not null)
            {
                try { pipeline.Dispose(); } catch (Exception) { /* best-effort */ }
            }
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        IEtwRuntimeProvider? provider;
        IRuntimeEventPipeline? pipeline;
        BehavioralRuntimeBinding? binding;
        IAmsiTelemetryProvider? amsiProvider;
        AmsiRuntimeBridge? amsiBridge;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            // Detach any ETW provider/pipeline/binding so teardown happens once, outside the lock.
            provider = _etwProvider;
            pipeline = _runtimeEventPipeline;
            binding = _behavioralBinding;
            amsiProvider = _amsiProvider;
            amsiBridge = _amsiBridge;
            _etwProvider = null;
            _runtimeEventPipeline = null;
            _behavioralBinding = null;
            _amsiProvider = null;
            _amsiBridge = null;
            _memoryBridge = null;
            _behavioralState = BehavioralRuntimeBindingState.Stopped;
            if (amsiProvider is not null) _amsiState = RuntimeProviderState.Stopped;

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

        // Graceful, fail-closed teardown of optional runtime telemetry (no-op when absent).
        // Stop the behavioral consumer first (unsubscribe) before the producer/pipeline.
        if (binding is not null)
        {
            try { await binding.StopAsync(cancellationToken).ConfigureAwait(false); } catch (Exception) { /* teardown is best-effort */ }
            try { binding.Dispose(); } catch (Exception) { /* teardown is best-effort */ }
        }
        if (amsiBridge is not null)
        {
            try { amsiBridge.Dispose(); } catch (Exception) { /* teardown is best-effort */ }
        }
        if (amsiProvider is not null)
        {
            try { amsiProvider.Stop(); } catch (Exception) { /* teardown is best-effort */ }
            try { amsiProvider.Dispose(); } catch (Exception) { /* teardown is best-effort */ }
        }
        if (provider is not null)
            await EtwRuntimeProviderHost.SafeStopAsync(provider, cancellationToken).ConfigureAwait(false);
        if (pipeline is not null)
        {
            try { pipeline.Dispose(); } catch (Exception) { /* teardown is best-effort */ }
        }
    }

    /// <summary>
    /// Submit explicitly obtained script content to the in-memory AMSI
    /// analyzer. This observes only; it never blocks script execution and
    /// never returns a malware verdict.
    /// </summary>
    public int SubmitAmsiContent(string source, string content, int processId)
    {
        IAmsiTelemetryProvider? provider;
        lock (_gate)
        {
            if (_disposed) return 0;
            provider = _amsiProvider;
        }

        if (provider is null) return 0;

        try
        {
            var published = provider.SubmitContent(source, content, processId);
            lock (_gate)
            {
                _behavioralState = _behavioralBinding?.GetStatus().State
                    ?? _behavioralState;
                _lastUpdatedUtc = DateTimeOffset.UtcNow;
            }
            return published;
        }
        catch (Exception ex)
        {
            AddWarning($"AMSI content submission failed ({ex.GetType().Name}: {ex.Message}); no verdict or action was produced.");
            return 0;
        }
    }

    /// <summary>
    /// Bounded snapshot for diagnostics/tests. Every returned item is
    /// evidence-only and has IsConfirmedMalware=false by construction.
    /// </summary>
    public IReadOnlyList<BehavioralRuntimeEvidence> GetRecentRuntimeEvidence()
    {
        lock (_gate)
        {
            return _behavioralBinding?.GetRecentEvidence()
                ?? Array.Empty<BehavioralRuntimeEvidence>();
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
                "Realtime file blocking / system AMSI registration is deferred; in-memory AMSI observation is reported separately."),
            BuildRuntimeTelemetryModule(),
            BuildMemoryRuntimeModule(),
            BuildAmsiRuntimeModule(),
            BuildBehavioralRuntimeModule(),
        };
    }

    /// <summary>
    /// Reports the behavioral runtime correlation module honestly. It is bound to
    /// the SAME runtime-event pipeline used by ETW, memory, and AMSI. It is
    /// passive/evidence-only: it consumes telemetry and produces evidence that NEVER
    /// confirms malware on its own and never drives any action — so it is reported
    /// as <see cref="RuntimeModuleAvailability.Passive"/> when running (never
    /// <see cref="RuntimeModuleAvailability.Available"/>) and Degraded otherwise.
    /// </summary>
    private DataVangerRuntimeModuleStatus BuildBehavioralRuntimeModule()
    {
        if (_state == DataVangerServiceState.NotStarted)
        {
            return new DataVangerRuntimeModuleStatus(
                "BehavioralRuntimePlaceholder",
                RuntimeModuleAvailability.NotImplemented,
                "Behavioral runtime correlation starts with the resident runtime pipeline.");
        }

        return _behavioralState is BehavioralRuntimeBindingState.Running
                or BehavioralRuntimeBindingState.Passive
                or BehavioralRuntimeBindingState.DevelopmentSafe
            ? new DataVangerRuntimeModuleStatus(
                "BehavioralRuntime",
                RuntimeModuleAvailability.Passive,
                "Behavioral runtime correlation active: consumes ETW, memory, and in-memory AMSI telemetry; passive, bounded, heuristic-only; never confirms malware and performs no blocking or quarantine.")
            : new DataVangerRuntimeModuleStatus(
                "BehavioralRuntime",
                RuntimeModuleAvailability.Degraded,
                $"Behavioral runtime correlation enabled but binding state is '{_behavioralState}'; degraded to safe fallback. No active protection.");
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

    private DataVangerRuntimeModuleStatus BuildMemoryRuntimeModule()
    {
        if (!_configuration.EnableMemoryScanPass)
        {
            return new DataVangerRuntimeModuleStatus(
                "MemoryRuntime",
                RuntimeModuleAvailability.Passive,
                "Resident memory bridge is wired; the bounded startup scan pass is disabled by default. No active protection.");
        }

        if (_memoryPassAttempted
            && _memoryScanResult is not null
            && !_memoryScanResult.IsDegraded
            && string.IsNullOrWhiteSpace(_memoryLastError))
        {
            return new DataVangerRuntimeModuleStatus(
                "MemoryRuntime",
                RuntimeModuleAvailability.Passive,
                $"One bounded startup pass completed: {_memoryScanResult.ProcessesScanned} processes, {_memoryScanResult.Findings.Count} heuristic findings. Evidence only; never confirms malware.");
        }

        var detail = string.IsNullOrWhiteSpace(_memoryLastError)
            ? (_memoryPassAttempted
                ? "The bounded startup pass did not complete with a usable reader."
                : "The bounded startup pass has not run.")
            : _memoryLastError;
        return new DataVangerRuntimeModuleStatus(
            "MemoryRuntime",
            RuntimeModuleAvailability.Degraded,
            $"Memory runtime enabled but degraded ({detail}). No active protection and no automatic action.");
    }

    private DataVangerRuntimeModuleStatus BuildAmsiRuntimeModule()
    {
        bool realIngest = string.Equals(_amsiProviderName, "pipe-ingest-amsi", StringComparison.Ordinal);
        string runningDetail = realIngest
            ? "Real AMSI provider ingest listener active (Windows): the native amsi.dll shim always returns CLEAN and only forwards a bounded content prefix; passive, bounded, rate-limited, never blocks scripts and never confirms malware."
            : "In-memory AMSI content observation is ready for explicit submissions; passive, bounded, never blocks scripts and never confirms malware.";
        string degradedNoun = realIngest ? "Real AMSI provider ingest" : "In-memory AMSI observation";

        return _amsiState is RuntimeProviderState.Running or RuntimeProviderState.RunningMock
            ? new DataVangerRuntimeModuleStatus(
                "AmsiRuntime",
                RuntimeModuleAvailability.Passive,
                runningDetail)
            : new DataVangerRuntimeModuleStatus(
                "AmsiRuntime",
                RuntimeModuleAvailability.Degraded,
                string.IsNullOrWhiteSpace(_amsiLastError)
                    ? $"{degradedNoun} state is '{_amsiState}'. No active protection."
                    : $"{degradedNoun} degraded ({_amsiLastError}). No active protection.");
    }

    public void Dispose()
    {
        IEtwRuntimeProvider? provider;
        IRuntimeEventPipeline? pipeline;
        BehavioralRuntimeBinding? binding;
        IAmsiTelemetryProvider? amsiProvider;
        AmsiRuntimeBridge? amsiBridge;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            provider = _etwProvider;
            pipeline = _runtimeEventPipeline;
            binding = _behavioralBinding;
            amsiProvider = _amsiProvider;
            amsiBridge = _amsiBridge;
            _etwProvider = null;
            _runtimeEventPipeline = null;
            _behavioralBinding = null;
            _amsiProvider = null;
            _amsiBridge = null;
            _memoryBridge = null;
            _behavioralState = BehavioralRuntimeBindingState.Stopped;
            if (amsiProvider is not null) _amsiState = RuntimeProviderState.Stopped;
            if (_state != DataVangerServiceState.Stopped
                && _state != DataVangerServiceState.NotStarted)
            {
                _state = DataVangerServiceState.Stopped;
                _lastUpdatedUtc = DateTimeOffset.UtcNow;
            }
        }

        // Best-effort, fail-closed teardown of any opt-in runtime telemetry.
        // Stop the behavioral consumer first (unsubscribe), then producer/pipeline.
        if (binding is not null)
        {
            try { binding.Dispose(); } catch (Exception) { /* Dispose never throws */ }
        }
        if (amsiBridge is not null)
        {
            try { amsiBridge.Dispose(); } catch (Exception) { /* Dispose never throws */ }
        }
        if (amsiProvider is not null)
        {
            try { amsiProvider.Stop(); } catch (Exception) { /* Dispose never throws */ }
            try { amsiProvider.Dispose(); } catch (Exception) { /* Dispose never throws */ }
        }
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

    private void AddWarning(string warning)
    {
        if (string.IsNullOrWhiteSpace(warning)) return;
        lock (_gate)
        {
            _warnings.Add(warning);
            _lastUpdatedUtc = DateTimeOffset.UtcNow;
        }
    }

    /// <summary>
    /// Selects the single AMSI provider for this runtime. The real ingest
    /// provider is chosen only when explicitly opted in AND the runtime is a
    /// genuine Windows service (never in Development/Console, never in the WPF
    /// UI process); otherwise the in-memory analyzer is used. Because exactly
    /// one provider is created, the two paths never run in parallel and events
    /// are never duplicated.
    /// </summary>
    private IAmsiTelemetryProvider CreateConfiguredAmsiProvider()
        => AmsiProviderFactory.Create(
            _configuration.EnableRealAmsiProvider && _mode == DataVangerRuntimeMode.Service
                ? AmsiProviderMode.RealProvider
                : AmsiProviderMode.Auto);

    private static MemoryScannerOptions CreateBoundedMemoryOptions(MemoryScannerOptions? options)
    {
        var source = options ?? new MemoryScannerOptions();
        return new MemoryScannerOptions
        {
            Enabled = source.Enabled,
            MaxProcesses = Math.Clamp(source.MaxProcesses, 1, 256),
            MaxRegionsPerProcess = Math.Clamp(source.MaxRegionsPerProcess, 1, 4096),
            MaxBytesPerRegion = Math.Clamp(source.MaxBytesPerRegion, 1, 1024 * 1024),
            MaxTotalBytes = Math.Clamp(source.MaxTotalBytes, 1, 64L * 1024 * 1024),
            OverallTimeout = ClampDuration(source.OverallTimeout, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(1)),
            PerProcessTimeout = ClampDuration(source.PerProcessTimeout, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(15)),
            HighEntropyThreshold = Math.Clamp(source.HighEntropyThreshold, 0, 8),
            SkipTrustedSignedProcesses = source.SkipTrustedSignedProcesses,
            SkipProtectedProcesses = source.SkipProtectedProcesses,
            MaxFindings = Math.Clamp(source.MaxFindings, 1, 4096),
        };
    }

    private static TimeSpan ClampDuration(TimeSpan value, TimeSpan fallback, TimeSpan maximum)
    {
        if (value <= TimeSpan.Zero) return fallback;
        return value > maximum ? maximum : value;
    }
}
