using System.Threading;
using System.Threading.Tasks;
using DataVanger.Infrastructure.Ipc;
using DataVanger.Shared.Ipc;

namespace DataVanger.Service.Ipc;

/// <summary>
/// Handles explicit Pause/Resume realtime-protection commands. These record the
/// user's intent on the service. Honest behavior: the handler never fabricates
/// active protection and never starts a background loop. The service remains
/// authoritative for the actual runtime state.
/// </summary>
internal sealed class ProtectionCommandHandler
{
    private readonly DataVangerServiceCommandContext _context;

    public ProtectionCommandHandler(DataVangerServiceCommandContext context)
    {
        _context = context;
    }

    public Task<DataVangerResponse> HandleAsync(DataVangerRequest request, CancellationToken cancellationToken)
    {
        ServiceCommandResult result;
        switch (request.CommandType)
        {
            case DataVangerCommandType.PauseRealtimeProtection:
                _context.Protection.RequestPause();
                result = ServiceCommandResult.Ok("Realtime protection pause requested.");
                break;

            case DataVangerCommandType.ResumeRealtimeProtection:
                _context.Protection.RequestResume();
                result = ServiceCommandResult.Ok("Realtime protection resume requested.");
                break;

            default:
                return Task.FromResult(DataVangerResponse.Error(
                    request.RequestId, IpcStatusCode.Unsupported,
                    $"Protection handler does not support '{request.CommandType}'.", "UnsupportedCommand"));
        }

        return Task.FromResult(DataVangerResponse.Ok(
            request.RequestId, IpcSerialization.SerializePayload(result), result.Message));
    }
}
