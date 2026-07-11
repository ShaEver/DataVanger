using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Updates.SignedUpdates;
using DataVanger.Shared.Updates;
using Xunit;

// Phase 14 — bounded, opt-in, fail-closed HTTP transport for signed updates.
//
// Every fixture is offline: a mock HttpMessageHandler serves canned bytes (or throws),
// so NO real socket/DNS/internet is used. Manifests are signed with an EPHEMERAL RSA key
// generated in-process (no shared private material). The transport only fetches bytes; the
// real SignedUpdateService + verifiers make every trust decision, so the service-level tests
// here prove signature verification, anti-downgrade, and last-known-good remain mandatory and
// upstream even when bytes arrive over HTTP. Filter: --filter "FullyQualifiedName~Update".
public class SignedUpdateHttpTransportTests
{
    private const string KeyId = "phase14-ephemeral-rsa";
    private const string FeedId = "datavanger-default-feed";
    private const string FeedUrl = "https://feed.local/dv/manifest.json";
    private const string ManifestPath = "/dv/manifest.json";
    private const string PackageRelPath = "feeds/hash-blacklist.json";
    private const string PackageAbsPath = "/dv/feeds/hash-blacklist.json";

    // Ephemeral, in-process key pair (PKCS#8 private + SubjectPublicKeyInfo public PEM).
    private static readonly (string PrivatePem, string PublicPem) Keys = MakeKeys();

    private static (string, string) MakeKeys()
    {
        using var rsa = RSA.Create(2048);
        return (rsa.ExportPkcs8PrivateKeyPem(), rsa.ExportSubjectPublicKeyInfoPem());
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────

    private static SignedManifestVerifier NewVerifier() =>
        new(new[] { new PinnedPublicKey(KeyId, SignedManifestVerifier.AlgorithmRsaPss, Keys.PublicPem) });

    private static SignedUpdateService NewService(
        InMemoryUpdateStateStore state, IUpdateTransport transport, UpdateMode mode = UpdateMode.AutoApplyFeedsOnly) =>
        new(new UpdatePolicy { Mode = mode, FeedId = FeedId },
            NewVerifier(), new UpdatePackageVerifier(), state, new InMemoryUpdateContentSink(), transport);

    private static HttpUpdateTransportOptions ActiveOptions(
        long maxManifestBytes = 512L * 1024, long maxPackageBytes = 128L * 1024 * 1024, TimeSpan? timeout = null) =>
        new()
        {
            Enabled = true,
            FeedUrl = FeedUrl,
            Timeout = timeout ?? TimeSpan.FromSeconds(30),
            MaxManifestSizeBytes = maxManifestBytes,
            MaxPackageSizeBytes = maxPackageBytes,
        };

    private static UpdateManifest BaseManifest(long sequence, string sha, long size,
        string relPath = PackageRelPath, bool required = true) => new()
    {
        SchemaVersion = 1,
        FeedId = FeedId,
        Sequence = sequence,
        PublishedUtc = "2026-01-01T00:00:00Z",
        MinimumSupportedClientVersion = "0.0.0",
        Packages = new[]
        {
            new UpdatePackageEntry
            {
                Id = "hash-blacklist",
                Kind = UpdatePackageKind.HashBlacklist,
                Version = "2026.01.01." + sequence,
                Sha256 = sha,
                SizeBytes = size,
                RelativePath = relPath,
                Required = required,
            },
        },
    };

    private static UpdateManifest Sign(UpdateManifest m) =>
        UpdateManifestSigner.Sign(m, Keys.PrivatePem, SignedManifestVerifier.AlgorithmRsaPss, KeyId);

    private static UpdateManifest CloneWithSequence(UpdateManifest src, long newSequence) => new()
    {
        SchemaVersion = src.SchemaVersion,
        FeedId = src.FeedId,
        Sequence = newSequence,
        PublishedUtc = src.PublishedUtc,
        MinimumSupportedClientVersion = src.MinimumSupportedClientVersion,
        Packages = src.Packages,
        Signature = src.Signature,
    };

    private static (byte[] ManifestBytes, byte[] PackageContent) BuildSignedUpdate(long sequence)
    {
        var content = Encoding.UTF8.GetBytes("blacklist-v" + sequence);
        var sha = UpdatePackageVerifier.ComputeSha256Hex(content);
        var signed = Sign(BaseManifest(sequence, sha, content.LongLength));
        return (UpdateManifestJson.Serialize(signed), content);
    }

    private static HttpResponseMessage Ok(byte[] body) =>
        new(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };

    // Maps manifest + package paths to OK responses; everything else is 404.
    private static StubHandler MapHandler(byte[] manifestBytes, byte[] packageContent) =>
        new(req =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path == ManifestPath) return Ok(manifestBytes);
            if (path == PackageAbsPath) return Ok(packageContent);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;
        public int CallCount { get; private set; }

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) => _responder = responder;

        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            cancellationToken.ThrowIfCancellationRequested();
            return _responder(request);
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(_responder(request));
        }
    }

    // Content whose length is unknown (Content-Length absent) — forces the streaming cap.
    private sealed class NoLengthContent : HttpContent
    {
        private readonly byte[] _data;
        public NoLengthContent(byte[] data) => _data = data;

        protected override void SerializeToStream(Stream stream, TransportContext? context, CancellationToken cancellationToken)
            => stream.Write(_data, 0, _data.Length);

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            stream.Write(_data, 0, _data.Length);
            return Task.CompletedTask;
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false; // unknown length
        }
    }

    // ── opt-in / no-I/O ─────────────────────────────────────────────────────────────

    [Fact]
    public void DisabledOptions_PerformNoNetworkIO_ReturnNull()
    {
        var handler = new StubHandler(_ => Ok(new byte[] { 1, 2, 3 }));
        using var transport = new HttpUpdateTransport(HttpUpdateTransportOptions.Disabled, handler);
        Assert.Null(transport.GetManifestBytes());
        Assert.Equal(0, handler.CallCount); // never constructed a client, never called the handler
    }

    [Fact]
    public void EnabledButEmptyFeedUrl_PerformsNoIO()
    {
        var handler = new StubHandler(_ => Ok(new byte[] { 1 }));
        var opts = new HttpUpdateTransportOptions { Enabled = true, FeedUrl = "" };
        using var transport = new HttpUpdateTransport(opts, handler);
        Assert.Null(transport.GetManifestBytes());
        Assert.Equal(0, handler.CallCount);
    }

    [Fact]
    public void NonHttpsFeedUrl_Rejected_NoIO()
    {
        var handler = new StubHandler(_ => Ok(new byte[] { 1 }));
        var opts = new HttpUpdateTransportOptions { Enabled = true, FeedUrl = "http://feed.local/dv/manifest.json" };
        using var transport = new HttpUpdateTransport(opts, handler);
        Assert.Null(transport.GetManifestBytes());
        Assert.Equal(0, handler.CallCount);
    }

    [Fact]
    public void PolicyDisabledMode_ShortCircuits_BeforeAnyTransportCall()
    {
        var (mb, pc) = BuildSignedUpdate(50);
        var handler = MapHandler(mb, pc);
        using var transport = new HttpUpdateTransport(ActiveOptions(), handler);
        var state = new InMemoryUpdateStateStore();

        var result = NewService(state, transport, UpdateMode.Disabled).CheckAndApply();

        Assert.Equal(UpdateResultKind.Disabled, result.Kind);
        Assert.Equal(0, handler.CallCount); // disabled mode performs no I/O at all
    }

    // ── happy path through the real service ─────────────────────────────────────────

    [Fact]
    public void ValidSignedUpdateOverHttp_AppliedThroughService()
    {
        var (mb, pc) = BuildSignedUpdate(50);
        var handler = MapHandler(mb, pc);
        using var transport = new HttpUpdateTransport(ActiveOptions(), handler);
        var state = new InMemoryUpdateStateStore();

        var result = NewService(state, transport).CheckAndApply();

        Assert.True(result.Succeeded, result.Message);
        Assert.Equal(UpdateResultKind.Applied, result.Kind);
        Assert.Equal(50, state.GetCurrent(FeedId).HighestSequence);
        Assert.True(handler.CallCount >= 2); // manifest + package fetched
    }

    // ── verification stays mandatory (transport only fetches bytes) ──────────────────

    [Fact]
    public void TamperedManifestOverHttp_RejectedBySignature_StatePreserved()
    {
        var content = Encoding.UTF8.GetBytes("v50");
        var sha = UpdatePackageVerifier.ComputeSha256Hex(content);
        var signed = Sign(BaseManifest(50, sha, content.LongLength));
        var tampered = CloneWithSequence(signed, 9999); // same signature, different signed payload
        var mb = UpdateManifestJson.Serialize(tampered);

        var handler = MapHandler(mb, content);
        using var transport = new HttpUpdateTransport(ActiveOptions(), handler);
        var state = new InMemoryUpdateStateStore();

        var result = NewService(state, transport).CheckAndApply();

        Assert.False(result.Succeeded);
        Assert.Equal(UpdateResultKind.SignatureInvalid, result.Kind);
        Assert.False(state.GetCurrent(FeedId).HasState);
    }

    [Fact]
    public void TamperedPackageContentOverHttp_RejectedByHash_StatePreserved()
    {
        var (mb, _) = BuildSignedUpdate(50);
        // Same length as the signed content ("blacklist-v50"), different bytes => exercises the
        // SHA-256 comparison itself (not the size shortcut). Both reject as PackageHashMismatch.
        var handler = MapHandler(mb, Encoding.UTF8.GetBytes("blacklist-vXX"));
        using var transport = new HttpUpdateTransport(ActiveOptions(), handler);
        var state = new InMemoryUpdateStateStore();

        var result = NewService(state, transport).CheckAndApply();

        Assert.False(result.Succeeded);
        Assert.Equal(UpdateResultKind.PackageHashMismatch, result.Kind);
        Assert.False(state.GetCurrent(FeedId).HasState);
    }

    // ── anti-downgrade stays enforced upstream ───────────────────────────────────────

    [Fact]
    public void DowngradeOverHttp_Rejected_StatePreserved()
    {
        var state = new InMemoryUpdateStateStore();

        var (mb50, pc50) = BuildSignedUpdate(50);
        using (var good = new HttpUpdateTransport(ActiveOptions(), MapHandler(mb50, pc50)))
            Assert.Equal(UpdateResultKind.Applied, NewService(state, good).CheckAndApply().Kind);

        var (mb49, pc49) = BuildSignedUpdate(49);
        using var older = new HttpUpdateTransport(ActiveOptions(), MapHandler(mb49, pc49));
        var result = NewService(state, older).CheckAndApply();

        Assert.False(result.Succeeded);
        Assert.Equal(UpdateResultKind.DowngradeRejected, result.Kind);
        Assert.Equal(50, state.GetCurrent(FeedId).HighestSequence);
    }

    // ── bounded size ─────────────────────────────────────────────────────────────────

    [Fact]
    public void OversizedManifest_DeclaredLength_RejectedAtTransport()
    {
        var (mb, pc) = BuildSignedUpdate(50);
        using var transport = new HttpUpdateTransport(ActiveOptions(maxManifestBytes: 8), MapHandler(mb, pc));
        Assert.Null(transport.GetManifestBytes()); // ByteArrayContent declares a length > 8
    }

    [Fact]
    public void OversizedManifest_UnknownLength_RejectedByStreamingCap()
    {
        var (mb, _) = BuildSignedUpdate(50);
        var handler = new StubHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new NoLengthContent(mb) });
        using var transport = new HttpUpdateTransport(ActiveOptions(maxManifestBytes: 8), handler);
        Assert.Null(transport.GetManifestBytes());
    }

    [Fact]
    public void OversizedPackage_RejectedAtTransport()
    {
        var (mb, _) = BuildSignedUpdate(50);
        var handler = MapHandler(mb, new byte[4096]);
        using var transport = new HttpUpdateTransport(ActiveOptions(maxPackageBytes: 16), handler);
        var entry = new UpdatePackageEntry { RelativePath = PackageRelPath };
        Assert.Null(transport.GetPackageBytes(entry));
    }

    // ── redirect / scheme / path defenses ────────────────────────────────────────────

    [Fact]
    public void CrossHostRedirect_Rejected_NotFollowed()
    {
        var handler = new StubHandler(_ =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.Redirect);
            r.Headers.Location = new Uri("https://evil.example/dv/manifest.json");
            return r;
        });
        using var transport = new HttpUpdateTransport(ActiveOptions(), handler);
        Assert.Null(transport.GetManifestBytes());
        Assert.Equal(1, handler.CallCount); // fetched once; the redirect was NOT followed
    }

    [Fact]
    public void UnsafePackageRelativePath_Rejected_NoIO()
    {
        var handler = new StubHandler(_ => Ok(new byte[] { 1 }));
        using var transport = new HttpUpdateTransport(ActiveOptions(), handler);
        var entry = new UpdatePackageEntry { RelativePath = "../escape.json" };
        Assert.Null(transport.GetPackageBytes(entry));
        Assert.Equal(0, handler.CallCount); // rejected before any request
    }

    // ── timeout / network failure fail closed ────────────────────────────────────────

    [Fact]
    public void TimeoutOrCancellation_FailsClosed()
    {
        var handler = new StubHandler(_ => throw new TaskCanceledException("simulated timeout"));
        using var transport = new HttpUpdateTransport(ActiveOptions(timeout: TimeSpan.FromMilliseconds(50)), handler);
        Assert.Null(transport.GetManifestBytes());
    }

    [Fact]
    public void NetworkError_FailsClosed()
    {
        var handler = new StubHandler(_ => throw new HttpRequestException("connection refused"));
        using var transport = new HttpUpdateTransport(ActiveOptions(), handler);
        Assert.Null(transport.GetManifestBytes());
    }

    [Fact]
    public void ServerError5xx_FailsClosed()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using var transport = new HttpUpdateTransport(ActiveOptions(), handler);
        Assert.Null(transport.GetManifestBytes());
    }

    [Fact]
    public void LastKnownGoodPreserved_OnFetchFailureAfterSuccess()
    {
        var state = new InMemoryUpdateStateStore();
        var (mb, pc) = BuildSignedUpdate(50);
        using (var good = new HttpUpdateTransport(ActiveOptions(), MapHandler(mb, pc)))
            Assert.Equal(UpdateResultKind.Applied, NewService(state, good).CheckAndApply().Kind);

        using var failing = new HttpUpdateTransport(ActiveOptions(),
            new StubHandler(_ => throw new HttpRequestException("feed down")));
        var result = NewService(state, failing).CheckAndApply();

        Assert.False(result.Succeeded);
        Assert.Equal(UpdateResultKind.TransportUnavailable, result.Kind);
        Assert.Equal(50, state.GetCurrent(FeedId).HighestSequence); // unchanged
    }

    // ── anti-FP: update results are never a malware verdict ──────────────────────────

    [Fact]
    public void UpdateResults_AreNeverAMalwareVerdict()
    {
        var (mb, pc) = BuildSignedUpdate(50);
        using var ok = new HttpUpdateTransport(ActiveOptions(), MapHandler(mb, pc));
        var applied = NewService(new InMemoryUpdateStateStore(), ok).CheckAndApply();
        Assert.Equal(UpdateResultKind.Applied, applied.Kind);
        Assert.False(applied.IsConfirmedMalware);

        using var bad = new HttpUpdateTransport(ActiveOptions(),
            new StubHandler(_ => throw new HttpRequestException("down")));
        var rejected = NewService(new InMemoryUpdateStateStore(), bad).CheckAndApply();
        Assert.False(rejected.Succeeded);
        Assert.False(rejected.IsConfirmedMalware);
    }

    // ── config mapping clamps invalid values to safe bounds ──────────────────────────

    [Fact]
    public void OptionsCreate_ClampsInvalidValues_ToSafeDefaults()
    {
        var o = HttpUpdateTransportOptions.Create(
            enabled: true, feedUrl: "https://feed.local/dv/manifest.json",
            timeoutSeconds: 0, maxManifestSizeKB: -5, maxPackageSizeMB: 0);

        Assert.True(o.Enabled);
        Assert.Equal(TimeSpan.FromSeconds(30), o.Timeout);
        Assert.Equal(512L * 1024, o.MaxManifestSizeBytes);
        Assert.Equal(128L * 1024 * 1024, o.MaxPackageSizeBytes);
    }

    // ── no app-binary self-update ────────────────────────────────────────────────────

    [Fact]
    public void NoAppBinaryOrExecutableUpdatePackageKindExists()
    {
        // Structural guarantee: the type system cannot even represent an executable /
        // application-binary package, so the update channel can never self-update the app.
        string[] banned = { "AppBinary", "Application", "Executable", "Binary", "Exe", "Installer", "Msi", "Dll" };
        foreach (var name in Enum.GetNames(typeof(UpdatePackageKind)))
            foreach (var token in banned)
                Assert.False(
                    name.Contains(token, StringComparison.OrdinalIgnoreCase),
                    $"UpdatePackageKind.{name} must not represent an executable/app-binary package.");
    }

    [Fact]
    public void SignedManifest_WithUnknownPackageKind_RejectedOverHttp_StatePreserved()
    {
        // Even a VALIDLY signed manifest cannot introduce a non-allowlisted (would-be
        // executable) package kind: it is rejected at the kind gate, leaving state untouched.
        var content = Encoding.UTF8.GetBytes("would-be-binary");
        var sha = UpdatePackageVerifier.ComputeSha256Hex(content);
        var manifest = new UpdateManifest
        {
            SchemaVersion = 1,
            FeedId = FeedId,
            Sequence = 60,
            PublishedUtc = "2026-01-01T00:00:00Z",
            MinimumSupportedClientVersion = "0.0.0",
            Packages = new[]
            {
                new UpdatePackageEntry
                {
                    Id = "rogue",
                    Kind = UpdatePackageKind.Unknown,
                    Version = "2026.01.01.60",
                    Sha256 = sha,
                    SizeBytes = content.LongLength,
                    RelativePath = PackageRelPath,
                    Required = true,
                },
            },
        };
        var mb = UpdateManifestJson.Serialize(Sign(manifest));
        using var transport = new HttpUpdateTransport(ActiveOptions(), MapHandler(mb, content));
        var state = new InMemoryUpdateStateStore();

        var result = NewService(state, transport).CheckAndApply();

        Assert.False(result.Succeeded);
        Assert.Equal(UpdateResultKind.PackageKindRejected, result.Kind);
        Assert.False(state.GetCurrent(FeedId).HasState);
    }

    // ── file transport regression (still works through the real service) ─────────────

    [Fact]
    public void FileTransport_ValidSignedUpdate_AppliedThroughService()
    {
        var root = Path.Combine(Path.GetTempPath(), "dvtest_fileupd_" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(root);
            var (mb, pc) = BuildSignedUpdate(70);
            File.WriteAllBytes(Path.Combine(root, "manifest.json"), mb);

            var packagePath = Path.Combine(root, PackageRelPath.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(packagePath)!);
            File.WriteAllBytes(packagePath, pc);

            var transport = new FileUpdateTransport(root);
            var state = new InMemoryUpdateStateStore();

            var result = NewService(state, transport).CheckAndApply();

            Assert.True(result.Succeeded, result.Message);
            Assert.Equal(UpdateResultKind.Applied, result.Kind);
            Assert.Equal(70, state.GetCurrent(FeedId).HighestSequence);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
