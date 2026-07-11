using System.Threading;
using System.Threading.Tasks;
using DataVanger.Infrastructure.Ipc;
using DataVanger.Shared.Ipc;

namespace DataVanger.Service.Ipc;

/// <summary>
/// Handles update status/check commands. It adds NO new update-signature logic.
/// It reads an honest update status snapshot from the bound provider; when none
/// is bound it returns a disabled (but successful) status. A "check" returns the
/// same honest status — it never performs network I/O in this phase.
/// </summary>
internal sealed class UpdateCommandHandler
{
    private readonly DataVangerServiceCommandContext _context;

    public UpdateCommandHandler(DataVangerServiceCommandContext context)
    {
        _context = context;
    }

    public Task<DataVangerResponse> HandleAsync(DataVangerRequest request, CancellationToken cancellationToken)
    {
        UpdateStatusDto status = _context.UpdateStatusProvider?.Invoke() ?? new UpdateStatusDto
        {
            IsEnabled = false,
            Status = "Disabled",
            LastMessage = "No update provider bound to this host.",
        };

        DataVangerResponse response = request.CommandType switch
        {
            DataVangerCommandType.GetUpdateStatus => Ok(request, status),
            DataVangerCommandType.CheckForUpdates => Ok(request, status),
            _ => DataVangerResponse.Error(request.RequestId, IpcStatusCode.Unsupported,
                $"Update handler does not support '{request.CommandType}'.", "UnsupportedCommand"),
        };

        return Task.FromResult(response);
    }

    private static DataVangerResponse Ok<T>(DataVangerRequest request, T payload) where T : class
        => DataVangerResponse.Ok(request.RequestId, IpcSerialization.SerializePayload(payload));
}
