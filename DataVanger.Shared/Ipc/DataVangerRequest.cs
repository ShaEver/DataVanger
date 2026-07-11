using System;

namespace DataVanger.Shared.Ipc;

/// <summary>
/// Immutable request envelope sent from the UI to the service. The payload is
/// carried as a JSON string (<see cref="PayloadJson"/>) of a concrete DTO —
/// internal engine objects are never serialized and no polymorphic type
/// information is embedded.
/// </summary>
public sealed class DataVangerRequest
{
    /// <summary>Stable id used to correlate the response. Defaults to a GUID.</summary>
    public string RequestId { get; init; } = Guid.NewGuid().ToString("N");

    public DataVangerCommandType CommandType { get; init; } = DataVangerCommandType.Unknown;

    public DateTimeOffset CreatedUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Schema version of <see cref="PayloadJson"/>. Starts at 1.</summary>
    public int PayloadVersion { get; init; } = 1;

    /// <summary>
    /// JSON of a concrete payload DTO, or null/empty when the command needs
    /// no payload (for example <see cref="DataVangerCommandType.Ping"/>).
    /// </summary>
    public string? PayloadJson { get; init; }

    /// <summary>Friendly, non-authoritative client identifier for diagnostics.</summary>
    public string ClientName { get; init; } = "DataVanger.UI";

    public static DataVangerRequest Create(
        DataVangerCommandType commandType,
        string? payloadJson = null,
        string clientName = "DataVanger.UI",
        int payloadVersion = 1)
        => new()
        {
            CommandType = commandType,
            PayloadJson = payloadJson,
            ClientName = clientName,
            PayloadVersion = payloadVersion,
        };
}
