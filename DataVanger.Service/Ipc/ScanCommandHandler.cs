using System.Threading;
using System.Threading.Tasks;
using DataVanger.Infrastructure.Ipc;
using DataVanger.Shared.Ipc;

namespace DataVanger.Service.Ipc;

/// <summary>
/// Handles scan requests. The handler validates paths, registers a bounded
/// operation id, and returns immediately — it never blocks until completion and
/// never executes an arbitrary command. It does NOT rewrite or invoke the scan
/// engine in this phase; it only owns the request/operation contract.
/// </summary>
internal sealed class ScanCommandHandler
{
    private readonly DataVangerServiceCommandContext _context;

    public ScanCommandHandler(DataVangerServiceCommandContext context)
    {
        _context = context;
    }

    public Task<DataVangerResponse> HandleAsync(DataVangerRequest request, CancellationToken cancellationToken)
        => Task.FromResult(Handle(request));

    private DataVangerResponse Handle(DataVangerRequest request)
    {
        switch (request.CommandType)
        {
            case DataVangerCommandType.StartQuickScan:
            {
                string operationId = _context.Scans.Start(ScanRequestKind.Quick);
                var result = ServiceCommandResult.Ok("Quick scan queued.", operationId);
                return Ok(request, result);
            }

            case DataVangerCommandType.StartCustomScan:
            {
                if (!IpcSerialization.TryDeserializePayload<ScanRequestDto>(request.PayloadJson, out var dto) || dto is null)
                    return Bad(request, "Custom scan requires a valid ScanRequestDto payload.");

                if (!IpcSecurityPolicy.TryValidateScanPaths(dto.Paths, out var rejected))
                    return Bad(request, $"Custom scan path rejected: '{rejected}'.");

                string operationId = _context.Scans.Start(ScanRequestKind.Custom);
                var result = ServiceCommandResult.Ok("Custom scan queued.", operationId);
                return Ok(request, result);
            }

            case DataVangerCommandType.CancelScan:
            {
                if (!IpcSerialization.TryDeserializePayload<ScanOperationRequestDto>(request.PayloadJson, out var dto) || dto is null
                    || string.IsNullOrWhiteSpace(dto.OperationId))
                    return Bad(request, "CancelScan requires a valid operation id.");

                bool cancelled = _context.Scans.Cancel(dto.OperationId);
                var result = cancelled
                    ? ServiceCommandResult.Ok("Scan cancelled.", dto.OperationId)
                    : ServiceCommandResult.Fail("Unknown scan operation id.", "UnknownOperation");
                return Ok(request, result);
            }

            case DataVangerCommandType.GetScanStatus:
            {
                if (!IpcSerialization.TryDeserializePayload<ScanOperationRequestDto>(request.PayloadJson, out var dto) || dto is null
                    || string.IsNullOrWhiteSpace(dto.OperationId))
                    return Bad(request, "GetScanStatus requires a valid operation id.");

                var status = _context.Scans.Get(dto.OperationId) ?? new ScanStatusDto
                {
                    OperationId = dto.OperationId,
                    State = "NotFound",
                    Message = "No scan operation with that id.",
                };
                return Ok(request, status);
            }

            default:
                return DataVangerResponse.Error(request.RequestId, IpcStatusCode.Unsupported,
                    $"Scan handler does not support '{request.CommandType}'.", "UnsupportedCommand");
        }
    }

    private static DataVangerResponse Ok<T>(DataVangerRequest request, T payload) where T : class
        => DataVangerResponse.Ok(request.RequestId, IpcSerialization.SerializePayload(payload));

    private static DataVangerResponse Bad(DataVangerRequest request, string message)
        => DataVangerResponse.Error(request.RequestId, IpcStatusCode.BadRequest, message, "InvalidScanRequest");
}
