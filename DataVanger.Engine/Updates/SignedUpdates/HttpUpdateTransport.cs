using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Phase 14 — bounded, opt-in, fail-closed HTTP transport for signed updates.
///
/// This type ONLY fetches bytes. It performs NO trust decision of any kind:
/// manifest signature verification, package hash/size validation, anti-downgrade
/// sequencing, staging and state persistence all remain in
/// <see cref="SignedUpdateService"/> and the verifiers (exactly as for the
/// in-memory and file transports). A fetched manifest/package is only ever
/// applied if the existing upstream pipeline accepts it.
///
/// Safety properties enforced HERE (each is exercised by the active call chain):
/// <list type="bullet">
///   <item>Opt-in: inert unless <see cref="HttpUpdateTransportOptions.Enabled"/> is
///   true AND a syntactically valid <c>https</c> feed URL is supplied. Otherwise no
///   <see cref="HttpClient"/> is even constructed and every fetch returns null.</item>
///   <item>HTTPS only: a non-https feed (or package) URL is rejected; no request is made.</item>
///   <item>No redirects: automatic redirects are disabled on the handler AND any 3xx
///   response is rejected, which trivially prevents cross-host / SSRF redirect abuse.</item>
///   <item>Bounded size: a declared oversized <c>Content-Length</c> is rejected before
///   the body is read, and the body is streamed with a hard cap so a missing/lying
///   length cannot cause an unbounded buffer.</item>
///   <item>Bounded time: every request runs under a per-request timeout; expiry fails closed.</item>
///   <item>Fail closed: ANY transport-level failure (timeout, network error, bad scheme,
///   redirect, oversize, unsafe package path) returns null. Returning null never mutates
///   update state — the service treats a null manifest as <c>TransportUnavailable</c> and a
///   null required package as a verification failure, preserving last-known-good.</item>
/// </list>
///
/// TLS/HTTPS honesty: transport is restricted to the <c>https</c> scheme; the actual TLS
/// handshake and server-certificate validation rely on the platform's default
/// <see cref="SocketsHttpHandler"/> trust (no pinning). Tests inject a mock
/// <see cref="HttpMessageHandler"/> and therefore do no real network I/O.
/// </summary>
public sealed class HttpUpdateTransport : IUpdateTransport, IDisposable
{
    private readonly HttpUpdateTransportOptions _options;
    private readonly HttpClient? _http;
    private readonly Uri? _manifestUri;
    private readonly Uri? _packageBaseUri;
    private readonly bool _active;

    /// <param name="options">Bounds and opt-in flag. Never null.</param>
    /// <param name="handler">
    /// Optional message handler. Production passes null and a bounded
    /// <see cref="SocketsHttpHandler"/> is created (redirects disabled, no proxy). Tests
    /// inject a mock handler so no real socket is opened. An injected handler is NOT
    /// disposed by this transport.
    /// </param>
    public HttpUpdateTransport(HttpUpdateTransportOptions options, HttpMessageHandler? handler = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));

        // Become active ONLY for an explicit enable + a valid absolute https feed URL.
        // Anything else stays inert: no HttpClient, no I/O, every fetch returns null.
        if (_options.Enabled
            && !string.IsNullOrWhiteSpace(_options.FeedUrl)
            && Uri.TryCreate(_options.FeedUrl, UriKind.Absolute, out var feed)
            && IsHttps(feed))
        {
            _manifestUri = feed;
            _packageBaseUri = new Uri(feed, "."); // directory of the manifest URL

            var effectiveHandler = handler ?? new SocketsHttpHandler
            {
                AllowAutoRedirect = false,                  // defense in depth; we also reject any 3xx
                AutomaticDecompression = DecompressionMethods.None,
                ConnectTimeout = _options.Timeout,
                UseProxy = false,
            };
            _http = new HttpClient(effectiveHandler, disposeHandler: handler is null)
            {
                Timeout = Timeout.InfiniteTimeSpan, // a per-request CancellationToken governs the deadline
            };
            _active = true;
        }
    }

    public byte[]? GetManifestBytes()
    {
        if (!_active || _http is null || _manifestUri is null) return null; // disabled/unconfigured => no I/O
        return Fetch(_manifestUri, _options.MaxManifestSizeBytes);
    }

    public byte[]? GetPackageBytes(UpdatePackageEntry entry)
    {
        if (!_active || _http is null || _packageBaseUri is null) return null; // disabled/unconfigured => no I/O
        if (entry is null) return null;

        // Defense in depth: reuse the same relative-path policy the file transport and the
        // package verifier enforce (rejects "..", absolute, drive-letter and UNC paths).
        if (!UpdatePackageVerifier.IsSafeRelativePath(entry.RelativePath)) return null;
        if (!Uri.TryCreate(_packageBaseUri, entry.RelativePath, out var packageUri)) return null;

        // The resolved package URL must stay on the same https origin and under the feed's
        // directory — a crafted relative path can never reach another host or scheme.
        if (!IsSameOrigin(_packageBaseUri, packageUri)) return null;

        return Fetch(packageUri, _options.MaxPackageSizeBytes);
    }

    private byte[]? Fetch(Uri uri, long maxBytes)
    {
        if (!IsHttps(uri)) return null;

        try
        {
            using var cts = new CancellationTokenSource(_options.Timeout);
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            using var response = _http!.Send(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);

            // Reject ALL redirects (and any non-success). A fixed signed feed needs no redirect,
            // so this is the strongest, simplest defense against cross-host/SSRF redirect abuse.
            int status = (int)response.StatusCode;
            if (status >= 300 && status < 400) return null;
            if (!response.IsSuccessStatusCode) return null;

            // Pre-check the declared length when present; never trust it as the only guard.
            long? declared = response.Content.Headers.ContentLength;
            if (declared.HasValue && declared.Value > maxBytes) return null;

            using var body = response.Content.ReadAsStream(cts.Token);
            return ReadBounded(body, maxBytes, cts.Token);
        }
        catch (Exception ex) when (
            ex is HttpRequestException
            or OperationCanceledException   // includes TaskCanceledException raised on timeout/cancellation
            or IOException
            or InvalidOperationException
            or SocketException
            or UriFormatException)
        {
            // Fail closed. Returning null mutates no state; the service preserves last-known-good.
            return null;
        }
    }

    // Streams the body with a hard cap so a missing/incorrect Content-Length cannot
    // produce an unbounded buffer. Returns null (reject) the moment the cap is exceeded.
    private static byte[]? ReadBounded(Stream stream, long maxBytes, CancellationToken token)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = stream.Read(chunk, 0, chunk.Length)) > 0)
        {
            if (buffer.Length + read > maxBytes) return null; // oversize => reject, stop reading
            buffer.Write(chunk, 0, read);
            token.ThrowIfCancellationRequested();
        }
        return buffer.ToArray();
    }

    private static bool IsHttps(Uri uri) =>
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    private static bool IsSameOrigin(Uri baseUri, Uri candidate) =>
        IsHttps(candidate)
        && string.Equals(baseUri.Host, candidate.Host, StringComparison.OrdinalIgnoreCase)
        && baseUri.Port == candidate.Port
        && candidate.AbsolutePath.StartsWith(baseUri.AbsolutePath, StringComparison.Ordinal);

    public void Dispose() => _http?.Dispose();
}

/// <summary>
/// Bounds and opt-in flag for <see cref="HttpUpdateTransport"/>. A pure options record with
/// safe defaults: disabled, empty feed (no I/O), 30s timeout, 512 KB manifest cap, 128 MB
/// package cap. Lives in DataVanger.Engine; the mapping from <c>AppSettings</c> (which is in
/// the UI app layer that Engine does not reference) is performed by a future composition
/// layer via <see cref="Create"/>.
/// </summary>
public sealed record HttpUpdateTransportOptions
{
    public bool Enabled { get; init; }
    public string FeedUrl { get; init; } = string.Empty;
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
    public long MaxManifestSizeBytes { get; init; } = 512L * 1024;
    public long MaxPackageSizeBytes { get; init; } = 128L * 1024 * 1024;

    /// <summary>The explicit disabled default: no I/O, every fetch returns null.</summary>
    public static HttpUpdateTransportOptions Disabled { get; } = new();

    /// <summary>
    /// Build options from primitive config values (the shape an <c>AppSettings</c> mapping
    /// would supply). Any non-positive numeric value normalizes to the safe default, so
    /// invalid/missing config can never produce an unbounded fetch. A null/blank feed URL or
    /// <paramref name="enabled"/> = false yields an inert transport.
    /// </summary>
    public static HttpUpdateTransportOptions Create(
        bool enabled, string? feedUrl, int timeoutSeconds, int maxManifestSizeKB, int maxPackageSizeMB) => new()
    {
        Enabled = enabled,
        FeedUrl = feedUrl ?? string.Empty,
        Timeout = TimeSpan.FromSeconds(timeoutSeconds > 0 ? timeoutSeconds : 30),
        MaxManifestSizeBytes = (maxManifestSizeKB > 0 ? maxManifestSizeKB : 512) * 1024L,
        MaxPackageSizeBytes = (maxPackageSizeMB > 0 ? maxPackageSizeMB : 128) * 1024L * 1024L,
    };
}
