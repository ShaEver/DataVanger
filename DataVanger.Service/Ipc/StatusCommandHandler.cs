using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Infrastructure.Ipc;
using DataVanger.Shared.Ipc;
using DataVanger.Shared.Service;

namespace DataVanger.Service.Ipc;

/// <summary>
/// Handles the Status and Configuration commands. The service runtime is the
/// authoritative source; when no runtime is bound the handler returns an honest
/// "Unavailable" snapshot (never a fabricated active-protection claim).
/// </summary>
internal sealed class StatusCommandHandler
{
    private readonly DataVangerServiceCommandContext _context;

    public StatusCommandHandler(DataVangerServiceCommandContext context)
    {
        _context = context;
    }

    public Task<DataVangerResponse> HandleAsync(DataVangerRequest request, CancellationToken cancellationToken)
    {
        DataVangerResponse response = request.CommandType switch
        {
            DataVangerCommandType.GetServiceStatus => Ok(request, BuildSnapshot()),
            DataVangerCommandType.GetModuleStatus => Ok(request, new ModuleStatusListDto { Modules = BuildSnapshot().Modules }),
            DataVangerCommandType.GetProtectionStatus => Ok(request, BuildProtectionStatus()),
            DataVangerCommandType.GetConfigurationSummary => Ok(request, BuildConfigurationSummary()),
            _ => DataVangerResponse.Error(request.RequestId, IpcStatusCode.Unsupported,
                $"Status handler does not support '{request.CommandType}'.", "UnsupportedCommand"),
        };

        return Task.FromResult(response);
    }

    private ServiceStatusSnapshot BuildSnapshot()
    {
        var runtime = _context.Runtime;
        if (runtime is null)
        {
            return new ServiceStatusSnapshot
            {
                State = "Unavailable",
                Mode = "Unknown",
                HasActiveProtection = false,
                LastUpdatedUtc = DateTimeOffset.UtcNow,
                Warnings = new[] { "No runtime is bound to this host; status is unavailable." },
                Modules = Array.Empty<ModuleStatusDto>(),
            };
        }

        DataVangerServiceStatus status = runtime.GetStatusSnapshot();
        return new ServiceStatusSnapshot
        {
            State = status.State.ToString(),
            Mode = status.Mode.ToString(),
            HasActiveProtection = status.HasActiveProtection,
            LastUpdatedUtc = status.LastUpdatedUtc,
            StartedAtUtc = status.StartedAtUtc,
            Warnings = status.Warnings,
            Modules = status.Modules
                .Select(m => new ModuleStatusDto
                {
                    Name = m.Name,
                    Availability = m.Availability.ToString(),
                    Detail = m.Detail,
                    IsActiveProtection = m.IsActiveProtection,
                })
                .ToArray(),
        };
    }

    private ProtectionStatusDto BuildProtectionStatus()
    {
        var snapshot = BuildSnapshot();
        return new ProtectionStatusDto
        {
            HasActiveProtection = snapshot.HasActiveProtection,
            RealtimePauseRequested = _context.Protection.PauseRequested,
            State = snapshot.State,
            Detail = snapshot.HasActiveProtection
                ? "Service reports active protection."
                : "Service does not report active protection.",
        };
    }

    private ConfigurationSummaryDto BuildConfigurationSummary()
    {
        var snapshot = BuildSnapshot();
        IReadOnlyList<string> lines = _context.ConfigurationSummaryLines ?? new[]
        {
            $"State: {snapshot.State}",
            $"Mode: {snapshot.Mode}",
            $"ActiveProtection: {snapshot.HasActiveProtection}",
            $"Modules: {snapshot.Modules.Count}",
        };

        return new ConfigurationSummaryDto { Mode = snapshot.Mode, Lines = lines };
    }

    private static DataVangerResponse Ok<T>(DataVangerRequest request, T payload) where T : class
        => DataVangerResponse.Ok(request.RequestId, IpcSerialization.SerializePayload(payload));
}
