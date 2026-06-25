using System;

namespace DataVanger.Shared.Quarantine;

/// <summary>
/// An authenticated-encrypted payload. For AES-GCM, <see cref="Nonce"/> is the
/// 12-byte nonce, <see cref="Tag"/> is the 16-byte authentication tag, and
/// <see cref="CipherText"/> is the encrypted content. The tag authenticates the
/// ciphertext: any tampering fails decryption.
/// </summary>
public sealed class QuarantineEncryptedPayload
{
    public QuarantineEncryptedPayload(byte[] nonce, byte[] cipherText, byte[] tag, string algorithm)
    {
        Nonce = nonce;
        CipherText = cipherText;
        Tag = tag;
        Algorithm = algorithm;
    }

    public byte[] Nonce { get; }
    public byte[] CipherText { get; }
    public byte[] Tag { get; }
    public string Algorithm { get; }
}

/// <summary>
/// Symmetric key material used by the quarantine crypto provider. Two
/// independent 256-bit keys are derived from the protected master key: one for
/// payload encryption, one for metadata authentication.
///
/// IMPORTANT: instances hold raw key bytes. They must NEVER be logged,
/// serialized into records/reports, or emitted in audit events.
/// </summary>
public sealed class QuarantineKeyMaterial
{
    public QuarantineKeyMaterial(byte[] payloadKey, byte[] metadataKey)
    {
        if (payloadKey is null) throw new ArgumentNullException(nameof(payloadKey));
        if (metadataKey is null) throw new ArgumentNullException(nameof(metadataKey));
        PayloadKey = payloadKey;
        MetadataKey = metadataKey;
    }

    public byte[] PayloadKey { get; }
    public byte[] MetadataKey { get; }
}
