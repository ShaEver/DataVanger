using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Abstraction over where manifest/package bytes come from. Implementations
/// include in-memory, local-file-system, and an opt-in, bounded HTTPS transport
/// (<see cref="HttpUpdateTransport"/>).
///
/// A transport ONLY fetches raw bytes and makes NO trust decision: signature
/// verification, package hash/size validation, and anti-downgrade sequencing all
/// remain upstream in <see cref="SignedUpdateService"/> and the verifiers, so a
/// fetched manifest/package is applied only if that pipeline accepts it. A network
/// transport must be opt-in, bounded (size + timeout), HTTPS-only, reject redirects,
/// and fail closed (return null) on any error — returning null mutates no state and
/// preserves last-known-good.
/// </summary>
public interface IUpdateTransport
{
    /// <summary>Returns the raw manifest bytes, or null if unavailable.</summary>
    byte[]? GetManifestBytes();

    /// <summary>
    /// Returns the raw content bytes for a package entry, or null if the
    /// package is unavailable. Implementations should treat the entry's
    /// relative path as untrusted and never escape their own root.
    /// </summary>
    byte[]? GetPackageBytes(UpdatePackageEntry entry);
}
