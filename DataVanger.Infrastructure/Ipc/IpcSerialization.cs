using System;
using System.Text;
using System.Text.Json;
using DataVanger.Shared.Ipc;

namespace DataVanger.Infrastructure.Ipc;

/// <summary>
/// Deterministic, safe JSON serialization for the IPC boundary.
///
/// Safety properties:
///   - Only concrete DTO types are (de)serialized. There is no
///     <c>TypeNameHandling</c>, no polymorphic resolver, and no binder — a
///     malicious payload cannot select an arbitrary CLR type.
///   - Every serialized envelope is size-bounded against
///     <see cref="IpcOptions.MaxMessageBytes"/>.
///   - Deserialization failures are reported via <c>Try*</c> methods; they
///     never throw across the IPC boundary.
/// </summary>
public static class IpcSerialization
{
    private static readonly JsonSerializerOptions Options = new()
    {
        // Concrete types only; no polymorphism, no reference handling.
        PropertyNameCaseInsensitive = true,
        WriteIndented = false,
    };

    public static string SerializeRequest(DataVangerRequest request)
        => JsonSerializer.Serialize(request, Options);

    public static string SerializeResponse(DataVangerResponse response)
        => JsonSerializer.Serialize(response, Options);

    /// <summary>Serialize a concrete payload DTO to JSON.</summary>
    public static string SerializePayload<T>(T payload) where T : class
        => JsonSerializer.Serialize(payload, Options);

    /// <summary>
    /// Deserialize a concrete payload DTO. Returns false (and a null result)
    /// for null/empty/malformed JSON instead of throwing.
    /// </summary>
    public static bool TryDeserializePayload<T>(string? json, out T? payload) where T : class
    {
        payload = null;
        if (string.IsNullOrWhiteSpace(json)) return false;
        try
        {
            payload = JsonSerializer.Deserialize<T>(json, Options);
            return payload is not null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public static bool TryDeserializeRequest(string? json, out DataVangerRequest? request)
        => TryDeserializePayload(json, out request);

    public static bool TryDeserializeResponse(string? json, out DataVangerResponse? response)
        => TryDeserializePayload(json, out response);

    /// <summary>UTF-8 byte size of a string (the wire size for the size bound).</summary>
    public static int ByteSize(string? text)
        => string.IsNullOrEmpty(text) ? 0 : Encoding.UTF8.GetByteCount(text);
}
