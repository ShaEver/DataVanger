using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// (De)serializes an <see cref="UpdateManifest"/> to/from JSON bytes for
/// transport. IMPORTANT: this JSON is the wire format only. It is NEVER the
/// signed payload — signing/verification always go through
/// <see cref="UpdateCanonicalPayloadBuilder"/>, which is independent of this
/// serializer's property ordering or options.
/// </summary>
public static class UpdateManifestJson
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter() },
    };

    public static byte[] Serialize(UpdateManifest manifest)
    {
        if (manifest is null) throw new ArgumentNullException(nameof(manifest));
        var json = JsonSerializer.Serialize(manifest, Options);
        return Encoding.UTF8.GetBytes(json);
    }

    /// <summary>
    /// Deserializes manifest bytes. Returns false (never throws) for malformed
    /// or empty input.
    /// </summary>
    public static bool TryDeserialize(byte[]? manifestBytes, out UpdateManifest? manifest)
    {
        manifest = null;
        if (manifestBytes is null || manifestBytes.Length == 0) return false;
        try
        {
            manifest = JsonSerializer.Deserialize<UpdateManifest>(manifestBytes, Options);
            return manifest is not null;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }
}
