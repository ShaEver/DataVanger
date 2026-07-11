using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Infrastructure.Ipc;
using DataVanger.Shared.Ipc;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Service.Ipc;

/// <summary>
/// Handles quarantine commands by delegating to the existing Secure Quarantine
/// V2 service. It adds NO new quarantine logic, NO new cryptography, and NO
/// verdict changes. Restore preserves the existing safety guarantees (no blind
/// restore, no traversal, no silent overwrite) because it simply forwards an
/// explicit request to the service, which enforces them.
///
/// When no quarantine service is bound, every command degrades to a structured
/// "unsupported" response. Delete is not part of the Secure Quarantine V2 API,
/// so it is honestly reported as unsupported rather than faked.
/// </summary>
internal sealed class QuarantineCommandHandler
{
    private readonly DataVangerServiceCommandContext _context;

    public QuarantineCommandHandler(DataVangerServiceCommandContext context)
    {
        _context = context;
    }

    public async Task<DataVangerResponse> HandleAsync(DataVangerRequest request, CancellationToken cancellationToken)
    {
        var service = _context.Quarantine;
        if (service is null)
            return DataVangerResponse.Error(request.RequestId, IpcStatusCode.Unsupported,
                "Quarantine service is not available on this host.", "QuarantineUnavailable");

        IpcSerialization.TryDeserializePayload<QuarantineRequestDto>(request.PayloadJson, out var dto);
        dto ??= new QuarantineRequestDto { Operation = QuarantineOperation.List };

        switch (request.CommandType)
        {
            case DataVangerCommandType.ListQuarantineItems:
            {
                var entries = await service.ListAsync(cancellationToken).ConfigureAwait(false);
                var items = entries.Select(e => new QuarantineItemDto
                {
                    ItemId = e.QuarantineId,
                    OriginalPath = e.OriginalFileName,
                    State = e.RecordState.ToString(),
                    QuarantinedUtc = e.CreatedUtc,
                    DetectionSummary = e.ThreatClassification.ToString(),
                }).ToArray();
                return Ok(request, new QuarantineListDto { Items = items, TotalCount = items.Length });
            }

            case DataVangerCommandType.GetQuarantineItemDetails:
            {
                if (string.IsNullOrWhiteSpace(dto.ItemId))
                    return BadItemId(request);

                var record = await service.GetAsync(dto.ItemId, cancellationToken).ConfigureAwait(false);
                if (record is null)
                    return DataVangerResponse.Error(request.RequestId, IpcStatusCode.BadRequest,
                        "No quarantine item with that id.", "QuarantineItemNotFound");

                var item = new QuarantineItemDto
                {
                    ItemId = record.QuarantineId,
                    OriginalPath = record.OriginalPath,
                    State = record.RecordState.ToString(),
                    QuarantinedUtc = record.CreatedUtc,
                    DetectionSummary = record.DetectionSummary,
                };
                return Ok(request, item);
            }

            case DataVangerCommandType.RestoreQuarantineItem:
            {
                if (string.IsNullOrWhiteSpace(dto.ItemId))
                    return BadItemId(request);

                var restoreRequest = new QuarantineRestoreRequest
                {
                    QuarantineId = dto.ItemId,
                    DestinationPath = dto.DestinationPath,
                    AllowOverwrite = dto.AllowOverwrite,
                };

                var restore = await service.RestoreAsync(restoreRequest, cancellationToken).ConfigureAwait(false);
                var result = new ServiceCommandResult
                {
                    Success = restore.IsRestored,
                    Message = restore.Message,
                    OperationId = restore.QuarantineId,
                    ErrorCode = restore.IsRestored ? null : restore.Status.ToString(),
                };
                return Ok(request, result);
            }

            case DataVangerCommandType.DeleteQuarantineItem:
            {
                if (string.IsNullOrWhiteSpace(dto.ItemId))
                    return BadItemId(request);

                // Secure Quarantine V2 exposes no delete API in this checkpoint.
                // Honest response: unsupported. No new quarantine logic added.
                return DataVangerResponse.Error(request.RequestId, IpcStatusCode.Unsupported,
                    "Quarantine delete is not supported by the current quarantine service.", "QuarantineDeleteUnsupported");
            }

            default:
                return DataVangerResponse.Error(request.RequestId, IpcStatusCode.Unsupported,
                    $"Quarantine handler does not support '{request.CommandType}'.", "UnsupportedCommand");
        }
    }

    private static DataVangerResponse BadItemId(DataVangerRequest request)
        => DataVangerResponse.Error(request.RequestId, IpcStatusCode.BadRequest,
            "A valid quarantine item id is required.", "InvalidItemId");

    private static DataVangerResponse Ok<T>(DataVangerRequest request, T payload) where T : class
        => DataVangerResponse.Ok(request.RequestId, IpcSerialization.SerializePayload(payload));
}
