using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Infrastructure.Ipc;
using DataVanger.Shared.Ipc;

namespace DataVanger.Service.Ipc;

/// <summary>
/// Handles the Diagnostics commands: Ping, ExportDiagnosticBundle, and
/// ShutdownDevelopmentHost.
///
/// ShutdownDevelopmentHost affects ONLY a development/test host. On a production
/// service host the command is refused with a structured error — it can never
/// stop or disable a real installed Windows Service. The diagnostic bundle is a
/// bounded, read-only text summary; it never runs a shell or collects arbitrary
/// files.
/// </summary>
internal sealed class DiagnosticsCommandHandler
{
    private readonly DataVangerServiceCommandContext _context;

    public DiagnosticsCommandHandler(DataVangerServiceCommandContext context)
    {
        _context = context;
    }

    public Task<DataVangerResponse> HandleAsync(DataVangerRequest request, CancellationToken cancellationToken)
    {
        switch (request.CommandType)
        {
            case DataVangerCommandType.Ping:
            {
                var result = ServiceCommandResult.Ok("pong");
                return Task.FromResult(DataVangerResponse.Ok(request.RequestId, IpcSerialization.SerializePayload(result), "pong"));
            }

            case DataVangerCommandType.ExportDiagnosticBundle:
                return Task.FromResult(BuildBundle(request));

            case DataVangerCommandType.ShutdownDevelopmentHost:
                return Task.FromResult(HandleShutdown(request));

            default:
                return Task.FromResult(DataVangerResponse.Error(request.RequestId, IpcStatusCode.Unsupported,
                    $"Diagnostics handler does not support '{request.CommandType}'.", "UnsupportedCommand"));
        }
    }

    private DataVangerResponse BuildBundle(DataVangerRequest request)
    {
        var runtime = _context.Runtime;
        string state = runtime is null ? "Unavailable" : runtime.GetStatusSnapshot().State.ToString();

        var lines = new List<string>
        {
            $"HostKind: {_context.HostKind}",
            $"ServiceState: {state}",
            $"GeneratedUtc: {DateTimeOffset.UtcNow:O}",
        };

        var bundle = new DiagnosticsBundleDto
        {
            HostKind = _context.HostKind,
            ServiceState = state,
            Lines = lines,
        };

        return DataVangerResponse.Ok(request.RequestId, IpcSerialization.SerializePayload(bundle));
    }

    private DataVangerResponse HandleShutdown(DataVangerRequest request)
    {
        if (_context.IsProductionServiceHost)
        {
            // Hard refusal: ShutdownDevelopmentHost must never stop a production
            // service. This is a safety invariant, not a recoverable error.
            return DataVangerResponse.Error(request.RequestId, IpcStatusCode.Unsupported,
                "ShutdownDevelopmentHost is refused on a production service host.", "ProductionShutdownRefused");
        }

        _context.DevelopmentHostShutdownCallback?.Invoke();
        var result = ServiceCommandResult.Ok("Development/test host shutdown acknowledged.");
        return DataVangerResponse.Ok(request.RequestId, IpcSerialization.SerializePayload(result), result.Message);
    }
}
