using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Ipc;
using DataVanger.Shared.Remediation;

namespace DataVanger.ViewModels;

/// <summary>
/// Adapts the generic <see cref="IDataVangerServiceClient"/> to the Removal
/// Center gateway. It serializes the request DTO, sends the single
/// <see cref="DataVangerCommandType.ExecuteRemediationAction"/> command, and
/// deserializes the response DTO. The wire format matches the service's
/// IpcSerialization (System.Text.Json, case-insensitive property names, numeric
/// enums), so requests/responses round-trip across the boundary.
///
/// This adapter holds no privilege and references no engine type: it only forwards
/// a Shared DTO over the Shared IPC client interface. The concrete client
/// (e.g. the named-pipe client) is injected by application composition.
/// </summary>
public sealed class RemovalCenterService : IRemovalCenterService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly IDataVangerServiceClient _client;

    public RemovalCenterService(IDataVangerServiceClient client)
        => _client = client ?? throw new ArgumentNullException(nameof(client));

    public bool IsAvailable => _client.IsAvailable;

    public async Task<RemediationExecutionResponseDto?> ExecuteAsync(
        RemediationExecutionRequestDto request,
        CancellationToken cancellationToken = default)
    {
        if (request is null) return null;

        string payload = JsonSerializer.Serialize(request, JsonOptions);
        var ipcRequest = DataVangerRequest.Create(DataVangerCommandType.ExecuteRemediationAction, payload);

        DataVangerResponse response = await _client.SendAsync(ipcRequest, cancellationToken).ConfigureAwait(false);
        if (response?.PayloadJson is null) return null;

        try
        {
            return JsonSerializer.Deserialize<RemediationExecutionResponseDto>(response.PayloadJson, JsonOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
