using System;
using System.IO;

namespace DataVanger.Shared.Quarantine;

/// <summary>
/// Authenticated encryption + integrity primitives for quarantine. The default
/// implementation uses AES-256-GCM for payloads (encrypt + authenticate in one
/// pass) and HMAC-SHA256 for metadata. Encryption is never performed without
/// authentication.
/// </summary>
public interface IQuarantineCryptoProvider
{
    string PayloadEncryptionAlgorithm { get; }
    string PayloadAuthenticationAlgorithm { get; }
    string MetadataIntegrityAlgorithm { get; }

    QuarantineEncryptedPayload EncryptPayload(byte[] plaintext, byte[] payloadKey);

    /// <summary>
    /// Decrypts and verifies the payload. Throws
    /// <see cref="QuarantineCryptoException"/> when authentication fails (tamper
    /// detected) — callers translate that into a structured integrity failure.
    /// </summary>
    byte[] DecryptPayload(QuarantineEncryptedPayload payload, byte[] payloadKey);

    byte[] ComputeMetadataTag(byte[] canonicalMetadata, byte[] metadataKey);

    bool VerifyMetadataTag(byte[] canonicalMetadata, byte[] metadataKey, byte[] expectedTag);

    string ComputeSha256Hex(Stream content);

    string ComputeSha256Hex(byte[] content);
}

/// <summary>Raised when authenticated decryption fails (payload tamper/corruption).</summary>
public sealed class QuarantineCryptoException : Exception
{
    public QuarantineCryptoException(string message) : base(message) { }
    public QuarantineCryptoException(string message, Exception inner) : base(message, inner) { }
}
