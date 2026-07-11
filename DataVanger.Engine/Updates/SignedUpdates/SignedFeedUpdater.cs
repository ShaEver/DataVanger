using System.Collections.Generic;
using DataVanger.Shared.RuntimeEvents;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Composition factory that wires the signed-update pipeline into a ready-to-run
/// <see cref="ISignedUpdateService"/>: pinned-key manifest verification, package verification,
/// durable state (anti-downgrade / last-known-good), and the filesystem apply bridge that
/// projects verified packages into the signature root (<see cref="FileSystemSignatureUpdateSink"/>).
///
/// This is the layer the README/AppSettings described as deferred — it lets the app actually
/// distribute a real signed feed on top of the bundled baseline. Trust is unchanged: only a
/// manifest signed by a <see cref="PinnedPublicKey"/> is accepted, downgrades are rejected, and
/// nothing here can ever produce a malware verdict.
/// </summary>
public static class SignedFeedUpdater
{
    /// <summary>Wires the service over a caller-supplied transport (file/in-memory for tests, HTTP in production).</summary>
    public static ISignedUpdateService Create(
        UpdatePolicy policy,
        IEnumerable<PinnedPublicKey> pinnedKeys,
        IUpdateTransport transport,
        string signatureRoot,
        string stateDirectory,
        IRuntimeEventPublisher? eventPublisher = null)
        => new SignedUpdateService(
            policy,
            new SignedManifestVerifier(pinnedKeys),
            new UpdatePackageVerifier(),
            new FileSystemUpdateStateStore(stateDirectory),
            new FileSystemSignatureUpdateSink(signatureRoot),
            transport,
            eventPublisher);

    /// <summary>
    /// Wires the service over the bounded, opt-in <see cref="HttpUpdateTransport"/>. The caller
    /// owns the returned service; the HTTP transport it holds is disposable, so prefer
    /// <see cref="Create"/> with a <c>using</c> transport when you need deterministic disposal.
    /// </summary>
    public static ISignedUpdateService CreateHttp(
        UpdatePolicy policy,
        IEnumerable<PinnedPublicKey> pinnedKeys,
        HttpUpdateTransportOptions httpOptions,
        string signatureRoot,
        string stateDirectory,
        IRuntimeEventPublisher? eventPublisher = null)
        => Create(policy, pinnedKeys, new HttpUpdateTransport(httpOptions), signatureRoot, stateDirectory, eventPublisher);
}
