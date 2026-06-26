using DataVanger.Engine.Updates.SignedUpdates;
using DataVanger.Shared.Updates;

namespace DataVanger.Core;

/// <summary>
/// UI-layer glue that runs the signed-update pipeline from <see cref="AppSettings"/>.
///
/// When signed updates are enabled and fully configured (feed URL + pinned public key), it
/// composes <see cref="SignedFeedUpdater"/> over the bounded <see cref="HttpUpdateTransport"/>
/// and applies a verified feed into the engine's signature root — so the scanner picks the new
/// signatures up on the next load. When not configured it returns <c>null</c> and the caller
/// falls back to the legacy unsigned URL fetch, so default behaviour is unchanged.
/// </summary>
public static class SignedFeedUpdateRunner
{
    /// <summary>True only when signed updates are enabled AND a feed URL + pinned key/keyId are present.</summary>
    public static bool IsConfigured(AppSettings s) =>
        s.EnableHttpSignedUpdates
        && !string.IsNullOrWhiteSpace(s.SignedUpdateFeedUrl)
        && !string.IsNullOrWhiteSpace(s.SignedUpdatePublicKeyPem)
        && !string.IsNullOrWhiteSpace(s.SignedUpdateKeyId);

    /// <summary>
    /// Applies the signed feed. Returns the structured result, or <c>null</c> when signed updates
    /// are not configured (the caller should then use the legacy path). Never throws for normal
    /// update problems — those are returned as a failed <see cref="UpdateApplyResult"/>.
    /// </summary>
    public static UpdateApplyResult? TryApply(AppSettings s, string signatureRoot, string stateDirectory)
    {
        if (!IsConfigured(s)) return null;

        string algorithm = string.IsNullOrWhiteSpace(s.SignedUpdateAlgorithm)
            ? SignedManifestVerifier.AlgorithmRsaPss
            : s.SignedUpdateAlgorithm.Trim();

        var pinned = new[]
        {
            new PinnedPublicKey(s.SignedUpdateKeyId.Trim(), algorithm, s.SignedUpdatePublicKeyPem),
        };

        var httpOptions = HttpUpdateTransportOptions.Create(
            enabled: true,
            feedUrl: s.SignedUpdateFeedUrl,
            timeoutSeconds: s.SignedUpdateHttpTimeoutSeconds,
            maxManifestSizeKB: s.SignedUpdateMaxManifestSizeKB,
            maxPackageSizeMB: s.SignedUpdateMaxPackageSizeMB);

        var policy = new UpdatePolicy
        {
            Mode = UpdateMode.AutoApplyFeedsOnly,
            FeedId = string.IsNullOrWhiteSpace(s.SignedUpdateFeedId) ? "datavanger-default-feed" : s.SignedUpdateFeedId.Trim(),
        };

        // The HTTP transport owns a disposable HttpClient; dispose it after the one-shot check.
        using var transport = new HttpUpdateTransport(httpOptions);
        var service = SignedFeedUpdater.Create(policy, pinned, transport, signatureRoot, stateDirectory);
        return service.CheckAndApply();
    }
}
