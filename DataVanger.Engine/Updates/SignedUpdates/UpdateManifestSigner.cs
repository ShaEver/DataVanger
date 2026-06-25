using System;
using System.Security.Cryptography;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Tooling/test helper that signs a manifest's canonical payload with a
/// CALLER-SUPPLIED private key. It embeds NO key material of its own.
///
/// Production signing happens out-of-band on a controlled, offline machine; a
/// production private key must never be present in the app, tests, or any
/// shipped artifact. This helper exists so tests (and any future signing tool)
/// can produce valid fixtures from a private key they already hold.
/// </summary>
public static class UpdateManifestSigner
{
    /// <summary>
    /// Returns a copy of <paramref name="manifest"/> with a signature envelope
    /// over its canonical payload, produced with the supplied private key PEM.
    /// </summary>
    public static UpdateManifest Sign(UpdateManifest manifest, string privateKeyPem, string algorithm, string keyId)
    {
        if (manifest is null) throw new ArgumentNullException(nameof(manifest));
        if (string.IsNullOrWhiteSpace(privateKeyPem)) throw new ArgumentException("Private key PEM is required.", nameof(privateKeyPem));

        var payload = UpdateCanonicalPayloadBuilder.Build(manifest);
        byte[] signatureBytes = algorithm switch
        {
            SignedManifestVerifier.AlgorithmRsaPss => SignRsaPss(privateKeyPem, payload),
            SignedManifestVerifier.AlgorithmEcdsaP256 => SignEcdsaP256(privateKeyPem, payload),
            _ => throw new ArgumentException($"Unsupported signing algorithm '{algorithm}'.", nameof(algorithm)),
        };

        return new UpdateManifest
        {
            SchemaVersion = manifest.SchemaVersion,
            FeedId = manifest.FeedId,
            Sequence = manifest.Sequence,
            PublishedUtc = manifest.PublishedUtc,
            MinimumSupportedClientVersion = manifest.MinimumSupportedClientVersion,
            Packages = manifest.Packages,
            Signature = new UpdateManifestSignature
            {
                Algorithm = algorithm,
                KeyId = keyId,
                Value = Convert.ToBase64String(signatureBytes),
            },
        };
    }

    private static byte[] SignRsaPss(string privateKeyPem, byte[] payload)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        return rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    private static byte[] SignEcdsaP256(string privateKeyPem, byte[] payload)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(privateKeyPem);
        return ecdsa.SignData(payload, HashAlgorithmName.SHA256);
    }
}
