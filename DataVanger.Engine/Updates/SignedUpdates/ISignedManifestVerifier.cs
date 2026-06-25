using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Authenticates an <see cref="UpdateManifest"/> by reconstructing its
/// canonical payload and verifying the signature against a pinned public key.
/// Never throws for normal verification failures — it returns a structured
/// <see cref="UpdateVerificationResult"/>.
/// </summary>
public interface ISignedManifestVerifier
{
    UpdateVerificationResult Verify(UpdateManifest manifest);
}
