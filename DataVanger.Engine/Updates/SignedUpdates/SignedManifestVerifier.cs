using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Verifies update manifests using a pinned-key set.
///
/// Primary algorithm  : RSA-PSS with SHA-256 ("RSA-PSS-SHA256").
/// Secondary algorithm: ECDsa P-256 with SHA-256 ("ECDsa-P256-SHA256").
///
/// Only <see cref="System.Security.Cryptography"/> is used. No Ed25519, no
/// PKCS#1 v1.5, no third-party packages. The verifier reconstructs the
/// canonical payload from the deserialized manifest object — it NEVER verifies
/// over raw input bytes or untrusted JSON text.
/// </summary>
public sealed class SignedManifestVerifier : ISignedManifestVerifier
{
    public const string AlgorithmRsaPss = "RSA-PSS-SHA256";
    public const string AlgorithmEcdsaP256 = "ECDsa-P256-SHA256";

    private readonly Dictionary<string, PinnedPublicKey> _keysById;

    public SignedManifestVerifier(IEnumerable<PinnedPublicKey> pinnedKeys)
    {
        if (pinnedKeys is null) throw new ArgumentNullException(nameof(pinnedKeys));
        _keysById = new Dictionary<string, PinnedPublicKey>(StringComparer.Ordinal);
        foreach (var key in pinnedKeys)
        {
            if (key is null) continue;
            _keysById[key.KeyId] = key;
        }
    }

    public UpdateVerificationResult Verify(UpdateManifest manifest)
    {
        // 1. Structural / schema sanity. Malformed manifests are rejected
        //    safely (no throw).
        if (manifest is null)
            return UpdateVerificationResult.Invalid(UpdateResultKind.ManifestMalformed, "Manifest is null.");
        if (string.IsNullOrWhiteSpace(manifest.FeedId))
            return UpdateVerificationResult.Invalid(UpdateResultKind.ManifestMalformed, "Manifest feedId is missing.");
        if (manifest.SchemaVersion <= 0)
            return UpdateVerificationResult.Invalid(UpdateResultKind.ManifestMalformed, "Manifest schemaVersion is invalid.", manifest.FeedId);
        if (manifest.Sequence < 0)
            return UpdateVerificationResult.Invalid(UpdateResultKind.ManifestMalformed, "Manifest sequence is negative.", manifest.FeedId);
        if (manifest.Packages is null)
            return UpdateVerificationResult.Invalid(UpdateResultKind.ManifestMalformed, "Manifest packages collection is null.", manifest.FeedId);

        // 2. Signature presence.
        var signature = manifest.Signature;
        if (signature is null
            || string.IsNullOrWhiteSpace(signature.Value)
            || string.IsNullOrWhiteSpace(signature.Algorithm)
            || string.IsNullOrWhiteSpace(signature.KeyId))
        {
            return UpdateVerificationResult.Invalid(UpdateResultKind.ManifestUnsigned, "Manifest is unsigned.", manifest.FeedId, manifest.Sequence);
        }

        // 3. Pinned key lookup.
        if (!_keysById.TryGetValue(signature.KeyId, out var pinnedKey))
            return UpdateVerificationResult.Invalid(UpdateResultKind.UnknownKey, $"Unknown signing key id '{signature.KeyId}'.", manifest.FeedId, manifest.Sequence);

        // 4. Algorithm support and key/algorithm agreement.
        if (signature.Algorithm != AlgorithmRsaPss && signature.Algorithm != AlgorithmEcdsaP256)
            return UpdateVerificationResult.Invalid(UpdateResultKind.UnsupportedAlgorithm, $"Unsupported signature algorithm '{signature.Algorithm}'.", manifest.FeedId, manifest.Sequence);
        if (!string.Equals(signature.Algorithm, pinnedKey.Algorithm, StringComparison.Ordinal))
            return UpdateVerificationResult.Invalid(UpdateResultKind.UnsupportedAlgorithm, "Signature algorithm does not match the pinned key algorithm.", manifest.FeedId, manifest.Sequence);

        // 5. Reconstruct canonical payload from the manifest object.
        byte[] canonicalPayload;
        string canonicalSha256;
        try
        {
            canonicalPayload = UpdateCanonicalPayloadBuilder.Build(manifest);
            canonicalSha256 = UpdateCanonicalPayloadBuilder.ComputeCanonicalSha256(manifest);
        }
        catch (CanonicalizationException ex)
        {
            return UpdateVerificationResult.Invalid(UpdateResultKind.CanonicalizationFailed, ex.Message, manifest.FeedId, manifest.Sequence);
        }

        // 6. Decode the signature value.
        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromBase64String(signature.Value);
        }
        catch (FormatException)
        {
            return UpdateVerificationResult.Invalid(UpdateResultKind.SignatureInvalid, "Signature value is not valid base64.", manifest.FeedId, manifest.Sequence);
        }

        // 7. Cryptographic verification. Any crypto failure is contained and
        //    mapped to a structured invalid result (never an unhandled throw).
        bool verified;
        try
        {
            verified = signature.Algorithm == AlgorithmRsaPss
                ? VerifyRsaPss(pinnedKey.PublicKeyPem, canonicalPayload, signatureBytes)
                : VerifyEcdsaP256(pinnedKey.PublicKeyPem, canonicalPayload, signatureBytes);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            return UpdateVerificationResult.Invalid(UpdateResultKind.SignatureInvalid, "Signature verification failed: " + ex.Message, manifest.FeedId, manifest.Sequence, canonicalSha256);
        }

        if (!verified)
            return UpdateVerificationResult.Invalid(UpdateResultKind.SignatureInvalid, "Signature did not verify against the pinned key.", manifest.FeedId, manifest.Sequence, canonicalSha256);

        return UpdateVerificationResult.Valid(manifest.FeedId, manifest.Sequence, canonicalSha256);
    }

    private static bool VerifyRsaPss(string publicKeyPem, byte[] payload, byte[] signature)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);
        return rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    private static bool VerifyEcdsaP256(string publicKeyPem, byte[] payload, byte[] signature)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(publicKeyPem);
        return ecdsa.VerifyData(payload, signature, HashAlgorithmName.SHA256);
    }
}
