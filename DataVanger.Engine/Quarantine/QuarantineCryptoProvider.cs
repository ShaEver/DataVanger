using System;
using System.IO;
using System.Security.Cryptography;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Engine.Quarantine;

/// <summary>
/// Default quarantine crypto provider (Secure Quarantine V2).
///
/// Payload: AES-256-GCM authenticated encryption. A fresh random 96-bit nonce
/// is generated per payload; the 128-bit GCM tag authenticates the ciphertext.
/// There is no "encrypt without authenticate" path.
///
/// Metadata: HMAC-SHA256 over the exact canonical record bytes.
///
/// Hashing: SHA-256 (lowercase hex).
///
/// The provider never logs keys or plaintext.
/// </summary>
public sealed class QuarantineCryptoProvider : IQuarantineCryptoProvider
{
    private const int NonceSize = 12;  // 96-bit GCM nonce
    private const int TagSize = 16;    // 128-bit GCM tag

    public string PayloadEncryptionAlgorithm => "AES-256-GCM";
    public string PayloadAuthenticationAlgorithm => "AES-GCM-128-TAG";
    public string MetadataIntegrityAlgorithm => "HMACSHA256";

    public QuarantineEncryptedPayload EncryptPayload(byte[] plaintext, byte[] payloadKey)
    {
        if (plaintext is null) throw new ArgumentNullException(nameof(plaintext));
        if (payloadKey is null) throw new ArgumentNullException(nameof(payloadKey));

        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(payloadKey, TagSize);
        aes.Encrypt(nonce, plaintext, cipher, tag);

        return new QuarantineEncryptedPayload(nonce, cipher, tag, PayloadEncryptionAlgorithm);
    }

    public byte[] DecryptPayload(QuarantineEncryptedPayload payload, byte[] payloadKey)
    {
        if (payload is null) throw new ArgumentNullException(nameof(payload));
        if (payloadKey is null) throw new ArgumentNullException(nameof(payloadKey));

        if (payload.Nonce is null || payload.Nonce.Length != NonceSize ||
            payload.Tag is null || payload.Tag.Length != TagSize ||
            payload.CipherText is null)
        {
            throw new QuarantineCryptoException("Encrypted payload structure is invalid or corrupt.");
        }

        var plain = new byte[payload.CipherText.Length];
        try
        {
            using var aes = new AesGcm(payloadKey, TagSize);
            aes.Decrypt(payload.Nonce, payload.CipherText, payload.Tag, plain);
            return plain;
        }
        catch (CryptographicException ex)
        {
            // Authentication failed: the ciphertext, nonce, or tag was altered.
            throw new QuarantineCryptoException("Payload authentication failed (tamper or corruption detected).", ex);
        }
    }

    public byte[] ComputeMetadataTag(byte[] canonicalMetadata, byte[] metadataKey)
    {
        if (canonicalMetadata is null) throw new ArgumentNullException(nameof(canonicalMetadata));
        if (metadataKey is null) throw new ArgumentNullException(nameof(metadataKey));
        return HMACSHA256.HashData(metadataKey, canonicalMetadata);
    }

    public bool VerifyMetadataTag(byte[] canonicalMetadata, byte[] metadataKey, byte[] expectedTag)
    {
        if (canonicalMetadata is null || metadataKey is null || expectedTag is null) return false;
        var actual = HMACSHA256.HashData(metadataKey, canonicalMetadata);
        // Constant-time comparison to avoid leaking via timing.
        return CryptographicOperations.FixedTimeEquals(actual, expectedTag);
    }

    public string ComputeSha256Hex(Stream content)
    {
        if (content is null) throw new ArgumentNullException(nameof(content));
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(content);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public string ComputeSha256Hex(byte[] content)
    {
        if (content is null) throw new ArgumentNullException(nameof(content));
        var hash = SHA256.HashData(content);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
