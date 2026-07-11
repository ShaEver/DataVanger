using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Infrastructure.Ipc;
using DataVanger.Shared.Ipc;

namespace DataVanger.Service.Ipc;

/// <summary>
/// Handles bounded event/history queries. The result is always bounded: the
/// requested limit is clamped to <see cref="EventQueryRequestDto.MaxLimit"/> and
/// offset/limit pagination is applied. No unbounded history is ever returned and
/// no raw sensitive content is exposed (the events are already DTO-projected).
/// </summary>
internal sealed class EventQueryCommandHandler
{
    private readonly DataVangerServiceCommandContext _context;

    public EventQueryCommandHandler(DataVangerServiceCommandContext context)
    {
        _context = context;
    }

    public Task<DataVangerResponse> HandleAsync(DataVangerRequest request, CancellationToken cancellationToken)
    {
        if (request.CommandType != DataVangerCommandType.GetRecentEvents)
            return Task.FromResult(DataVangerResponse.Error(request.RequestId, IpcStatusCode.Unsupported,
                $"Event handler does not support '{request.CommandType}'.", "UnsupportedCommand"));

        IpcSerialization.TryDeserializePayload<EventQueryRequestDto>(request.PayloadJson, out var dto);
        dto ??= new EventQueryRequestDto();

        IReadOnlyList<SecurityEventDto> all = _context.RecentEventsProvider?.Invoke() ?? Array.Empty<SecurityEventDto>();

        int appliedLimit = Math.Min(Math.Max(1, dto.Limit), EventQueryRequestDto.MaxLimit);
        int offset = Math.Max(0, dto.Offset);

        var page = all
            .Skip(offset)
            .Take(appliedLimit)
            .ToArray();

        var resultDto = new EventQueryResultDto
        {
            Events = page,
            TotalAvailable = all.Count,
            AppliedLimit = appliedLimit,
        };

        return Task.FromResult(DataVangerResponse.Ok(request.RequestId, IpcSerialization.SerializePayload(resultDto)));
    }
}
