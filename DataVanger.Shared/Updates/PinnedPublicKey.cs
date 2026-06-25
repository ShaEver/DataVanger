using System;

namespace DataVanger.Shared.Updates;

/// <summary>
/// A pinned public key used to authenticate update manifests. This is a DTO:
/// it carries the PEM text and metadata only — the actual cryptographic import
/// and verification happen in the engine verifier (which keeps all crypto out
/// of the shared DTO layer).
///
/// The PEM may come from:
///   - an embedded production public-key placeholder shipped with the app, or
///   - a test-only fixture constant.
///
/// A production PRIVATE key must never be included here, in tests, or in any
/// shipped artifact.
/// </summary>
public sealed class PinnedPublicKey
{
    public PinnedPublicKey(string keyId, string algorithm, string publicKeyPem)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            throw new ArgumentException("Key id must be non-empty.", nameof(keyId));
        if (string.IsNullOrWhiteSpace(algorithm))
            throw new ArgumentException("Algorithm must be non-empty.", nameof(algorithm));
        if (string.IsNullOrWhiteSpace(publicKeyPem))
            throw new ArgumentException("Public key PEM must be non-empty.", nameof(publicKeyPem));

        KeyId = keyId.Trim();
        Algorithm = algorithm.Trim();
        PublicKeyPem = publicKeyPem;
    }

    public string KeyId { get; }

    /// <summary>Algorithm this key is valid for ("RSA-PSS-SHA256" / "ECDsa-P256-SHA256").</summary>
    public string Algorithm { get; }

    /// <summary>SubjectPublicKeyInfo PEM text.</summary>
    public string PublicKeyPem { get; }
}
