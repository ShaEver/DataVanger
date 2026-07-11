namespace DataVanger.Shared.Updates;

/// <summary>
/// The signature envelope of an <see cref="UpdateManifest"/>. The signature
/// covers the canonical payload of the manifest, NOT this envelope itself.
/// See <c>UpdateCanonicalPayloadBuilder</c> for the exact signed bytes.
/// </summary>
public sealed class UpdateManifestSignature
{
    /// <summary>
    /// Algorithm identifier. Supported values:
    ///   "RSA-PSS-SHA256"   (primary, required)
    ///   "ECDsa-P256-SHA256" (secondary, optional)
    /// </summary>
    public string Algorithm { get; init; } = string.Empty;

    /// <summary>Identifier of the pinned public key that signed the manifest.</summary>
    public string KeyId { get; init; } = string.Empty;

    /// <summary>Base64-encoded signature over the canonical payload.</summary>
    public string Value { get; init; } = string.Empty;
}
