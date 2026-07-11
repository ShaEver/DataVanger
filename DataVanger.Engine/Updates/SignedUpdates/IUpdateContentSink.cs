using System.Collections.Generic;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// A staged package: an authenticated manifest entry plus its validated
/// content bytes. Carries bytes, so it lives in the engine (apply) layer
/// rather than the shared DTO layer.
/// </summary>
public sealed class StagedPackage
{
    public StagedPackage(UpdatePackageEntry entry, byte[] content)
    {
        Entry = entry;
        Content = content;
    }

    public UpdatePackageEntry Entry { get; }
    public byte[] Content { get; }
}

/// <summary>
/// Receives validated content for atomic staging and commit, and supports
/// rollback restore. The default in-memory sink writes nothing to disk; a
/// file-system sink stages to a unique directory then atomically promotes it.
///
/// Staging/commit problems are expressed by THROWING — the service catches the
/// failure, leaves the previous active state untouched, and returns a
/// structured <see cref="UpdateResultKind.StagingFailed"/> result.
/// </summary>
public interface IUpdateContentSink
{
    /// <summary>Stage validated content for a pending sequence.</summary>
    void Stage(string feedId, long sequence, string canonicalManifestSha256, IReadOnlyList<StagedPackage> packages);

    /// <summary>Atomically promote the staged content to the active set.</summary>
    void Commit(string feedId, long sequence);

    /// <summary>Restore the previously committed (last-known-good) content.</summary>
    void Restore(string feedId);
}
