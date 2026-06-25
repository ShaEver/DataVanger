using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DataVanger.Shared.Quarantine;

/// <summary>
/// Canonical (deterministic) serialization for quarantine records and record
/// envelopes. The exact UTF-8 bytes produced by <see cref="SerializeRecord"/>
/// are what the metadata authentication tag protects, so the same options must
/// be used everywhere. Verification re-uses the stored bytes verbatim rather
/// than re-serializing, so it is robust against formatting drift.
/// </summary>
public static class QuarantineRecordSerializer
{
    private static readonly JsonSerializerOptions RecordOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Converters = { new JsonStringEnumConverter() },
    };

    private static readonly JsonSerializerOptions EnvelopeOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static byte[] SerializeRecord(QuarantineRecord record)
        => Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record, RecordOptions));

    public static QuarantineRecord DeserializeRecord(byte[] canonicalMetadata)
        => JsonSerializer.Deserialize<QuarantineRecord>(canonicalMetadata, RecordOptions)
           ?? throw new InvalidOperationException("Quarantine record could not be deserialized.");

    public static string SerializeEnvelope(QuarantineRecordEnvelope envelope)
        => JsonSerializer.Serialize(envelope, EnvelopeOptions);

    public static QuarantineRecordEnvelope? DeserializeEnvelope(string json)
        => JsonSerializer.Deserialize<QuarantineRecordEnvelope>(json, EnvelopeOptions);

    /// <summary>
    /// Parses an envelope JSON into a <see cref="QuarantineStoredRecord"/> (the
    /// signed bytes + tag). Returns null when the envelope itself is unparseable
    /// or structurally invalid. Never throws — a corrupt envelope is reported as
    /// a missing/structured failure by the caller, never as a crash.
    /// </summary>
    public static QuarantineStoredRecord? ToStoredRecord(string envelopeJson)
    {
        try
        {
            var envelope = DeserializeEnvelope(envelopeJson);
            if (envelope is null) return null;
            var canonical = envelope.GetRecordBytes();
            var tag = envelope.GetMetadataTag();
            if (canonical.Length == 0 || tag.Length == 0) return null;
            return new QuarantineStoredRecord(canonical, tag, envelope.MetadataIntegrityAlgorithm);
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>
/// On-disk envelope wrapping the canonical record bytes (UTF-8, base64-encoded
/// so the persisted bytes are reproduced exactly) and the metadata
/// authentication tag.
/// </summary>
public sealed class QuarantineRecordEnvelope
{
    public int EnvelopeVersion { get; set; } = 2;
    public string MetadataIntegrityAlgorithm { get; set; } = "HMACSHA256";

    /// <summary>Base64 of the exact canonical record bytes that the tag protects.</summary>
    public string RecordBase64 { get; set; } = string.Empty;

    /// <summary>Base64 of the HMAC tag over the canonical record bytes.</summary>
    public string MetadataTagBase64 { get; set; } = string.Empty;

    public byte[] GetRecordBytes() => Convert.FromBase64String(RecordBase64);
    public byte[] GetMetadataTag() => Convert.FromBase64String(MetadataTagBase64);

    public static QuarantineRecordEnvelope Create(byte[] canonicalMetadata, byte[] metadataTag, string algorithm)
        => new()
        {
            MetadataIntegrityAlgorithm = algorithm,
            RecordBase64 = Convert.ToBase64String(canonicalMetadata),
            MetadataTagBase64 = Convert.ToBase64String(metadataTag),
        };
}
