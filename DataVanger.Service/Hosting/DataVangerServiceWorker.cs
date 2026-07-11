using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Service;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace DataVanger.Service.Hosting;

/// <summary>
/// Hosted adapter that maps the generic-host / Windows-Service lifecycle onto
/// the existing <see cref="IDataVangerServiceRuntime"/> state machine.
///
/// Mapping:
///   - host start  → <see cref="IDataVangerServiceRuntime.StartAsync"/>
///   - host stop / SCM stop / Ctrl-C / SIGTERM → <see cref="IDataVangerServiceRuntime.StopAsync"/>
///
/// This adapter adds NO detection, NO automatic action, and NO telemetry-to-
/// verdict path. It only forwards lifecycle signals; the runtime owns its own
/// (idempotent, graceful) state transitions. Repeated stop is safe because the
/// runtime's StopAsync is idempotent.
/// </summary>
public sealed class DataVangerServiceWorker : IHostedService
{
    private readonly IDataVangerServiceRuntime _runtime;
    private readonly ILogger<DataVangerServiceWorker> _logger;

    public DataVangerServiceWorker(IDataVangerServiceRuntime runtime, ILogger<DataVangerServiceWorker> logger)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await _runtime.StartAsync(cancellationToken).ConfigureAwait(false);

        var snapshot = _runtime.GetStatusSnapshot();
        _logger.LogInformation(
            "DataVanger runtime started (mode={Mode}, state={State}).",
            _runtime.Mode, snapshot.State);

        // Surface runtime-telemetry (ETW) status to the host log. In service mode there
        // is no other live status surface, so this is how an operator confirms whether
        // the opt-in provider activated (Passive), degraded, or stayed off. A degraded
        // "RuntimeTelemetry" module (operator enabled ETW but it is not active) is logged
        // at Warning so it reaches the Windows Event Log at the default level.
        foreach (var module in snapshot.Modules)
        {
            if (module.Name is "RuntimeTelemetry" or "RuntimeTelemetryPlaceholder")
            {
                if (module.Name == "RuntimeTelemetry" && module.Availability != RuntimeModuleAvailability.Passive)
                    _logger.LogWarning("ETW runtime telemetry NOT active: {Availability} — {Detail}", module.Availability, module.Detail);
                else
                    _logger.LogInformation("ETW runtime telemetry: {Availability} — {Detail}", module.Availability, module.Detail);
            }
        }

        // Runtime warnings (including the exact ETW provider status on degrade) -> Event Log.
        foreach (var warning in snapshot.Warnings)
        {
            _logger.LogWarning("DataVanger runtime warning: {Warning}", warning);
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await _runtime.StopAsync(cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("DataVanger runtime stopped (state={State}).", _runtime.State);
    }
}
