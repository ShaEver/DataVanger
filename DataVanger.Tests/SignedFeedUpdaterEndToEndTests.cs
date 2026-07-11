using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using DataVanger.Core;
using DataVanger.Engine.Updates.SignedUpdates;
using DataVanger.Shared.Updates;

namespace DataVanger.Tests;

// F1 finalization — end-to-end proof of the signed-feed pipeline wired by SignedFeedUpdater:
// sign a manifest with a freshly generated key, run the REAL SignedUpdateService (verifier +
// anti-downgrade + package verifier + filesystem state store + FileSystemSignatureUpdateSink)
// over a network-free transport, and confirm the verified hashes are applied to the signature
// root and become visible to the scanner's SignatureDatabase. A manifest pinned to a different
// key is rejected and leaves signatures untouched. Filter: ~SignedFeedUpdater.
public class SignedFeedUpdaterEndToEndTests
{
    private const string FeedId = "datavanger-default-feed";
    private const string KeyId = "e2e-test-key-1";
    private const string RelPath = "feeds/hash-blacklist.json";
    private static readonly string MalwareHash = new string('D', 64);

    private static (string priv, string pub) NewRsaKeys()
    {
        using var rsa = RSA.Create(2048);
        return (rsa.ExportPkcs8PrivateKeyPem(), rsa.ExportSubjectPublicKeyInfoPem());
    }

    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "dvtest_signedfeed_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static void Cleanup(string root)
    {
        try { Directory.Delete(root, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort */ }
    }

    private static InMemoryUpdateTransport BuildSignedTransport(string privatePem, long sequence, byte[] packageContent)
    {
        var manifest = new UpdateManifest
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
                    Sha256 = UpdatePackageVerifier.ComputeSha256Hex(packageContent),
                    SizeBytes = packageContent.LongLength,
                    RelativePath = RelPath,
                    Required = true,
                },
            },
        };
        var signed = UpdateManifestSigner.Sign(manifest, privatePem, SignedManifestVerifier.AlgorithmRsaPss, KeyId);
        var manifestBytes = UpdateManifestJson.Serialize(signed);
        return new InMemoryUpdateTransport(manifestBytes, new Dictionary<string, byte[]> { [RelPath] = packageContent });
    }

    [Fact]
    public void VerifiedSignedFeed_AppliesHashes_AndScannerReadsThem()
    {
        var (priv, pub) = NewRsaKeys();
        var root = NewRoot();
        try
        {
            string sigRoot = Path.Combine(root, "Signatures");
            string stateDir = Path.Combine(root, "UpdateState");
            byte[] package = Encoding.ASCII.GetBytes("# signed feed\n" + MalwareHash + "\n");

            var transport = BuildSignedTransport(priv, sequence: 1, packageContent: package);
            var policy = new UpdatePolicy { Mode = UpdateMode.AutoApplyFeedsOnly, FeedId = FeedId };
            var pinned = new[] { new PinnedPublicKey(KeyId, SignedManifestVerifier.AlgorithmRsaPss, pub) };

            var service = SignedFeedUpdater.Create(policy, pinned, transport, sigRoot, stateDir);
            var result = service.CheckAndApply();

            Assert.True(result.Succeeded, result.Message);
            Assert.Equal(UpdateResultKind.Applied, result.Kind);
            Assert.True(SignatureDatabase.Load(sigRoot).IsKnownMalicious(MalwareHash));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void ManifestSignedByUnpinnedKey_IsRejected_AndSignaturesUnchanged()
    {
        var (signingPriv, _) = NewRsaKeys();
        var (_, otherPub) = NewRsaKeys(); // pin a DIFFERENT key -> signature cannot verify
        var root = NewRoot();
        try
        {
            string sigRoot = Path.Combine(root, "Signatures");
            string stateDir = Path.Combine(root, "UpdateState");
            byte[] package = Encoding.ASCII.GetBytes(MalwareHash + "\n");

            var transport = BuildSignedTransport(signingPriv, sequence: 1, packageContent: package);
            var policy = new UpdatePolicy { Mode = UpdateMode.AutoApplyFeedsOnly, FeedId = FeedId };
            var pinned = new[] { new PinnedPublicKey(KeyId, SignedManifestVerifier.AlgorithmRsaPss, otherPub) };

            var service = SignedFeedUpdater.Create(policy, pinned, transport, sigRoot, stateDir);
            var result = service.CheckAndApply();

            Assert.False(result.Succeeded);
            Assert.NotEqual(UpdateResultKind.Applied, result.Kind);
            Assert.False(SignatureDatabase.Load(sigRoot).IsKnownMalicious(MalwareHash));
            Assert.False(File.Exists(Path.Combine(sigRoot, FileSystemSignatureUpdateSink.MaliciousFeedFileName)));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void Runner_Disabled_PerformsZeroTransportCreationAndZeroWrites()
    {
        var settings = new AppSettings();
        string root = Path.Combine(Path.GetTempPath(), "dv-runner-disabled-" + Guid.NewGuid().ToString("N"));
        int factoryCalls = 0;

        var result = SignedFeedUpdateRunner.Run(settings, Path.Combine(root, "sig"), Path.Combine(root, "state"), _ =>
        {
            factoryCalls++;
            throw new InvalidOperationException("transport must not be constructed");
        });

        Assert.Equal(SignedFeedRunResult.ExitDisabled, result.ExitCode);
        Assert.Equal(SignedFeedConfigurationState.Disabled, result.Configuration.State);
        Assert.Equal(0, factoryCalls);
        Assert.False(Directory.Exists(root));
        Assert.Contains("Nenhuma solicitação de rede ou escrita", result.Message);
    }

    [Fact]
    public void Runner_IncompleteConfiguration_IsStableAndFailClosed()
    {
        var settings = new AppSettings { EnableHttpSignedUpdates = true };
        string root = Path.Combine(Path.GetTempPath(), "dv-runner-incomplete-" + Guid.NewGuid().ToString("N"));
        int factoryCalls = 0;

        var result = SignedFeedUpdateRunner.Run(settings, Path.Combine(root, "sig"), Path.Combine(root, "state"), _ =>
        {
            factoryCalls++;
            throw new InvalidOperationException("transport must not be constructed");
        });

        Assert.Equal(SignedFeedRunResult.ExitNotConfigured, result.ExitCode);
        Assert.Equal(0, factoryCalls);
        Assert.False(Directory.Exists(root));
        Assert.Contains("URL HTTPS válida", result.Message);
        Assert.Contains("key id", result.Message);
        Assert.Contains("chave pública pinada", result.Message);
    }

    [Fact]
    public void Runner_RefusesHttpBeforeTransportConstruction()
    {
        var (_, publicPem) = NewRsaKeys();
        var settings = CompleteSettings(publicPem);
        settings.SignedUpdateFeedUrl = "http://updates.example.test/manifest.json";
        int factoryCalls = 0;

        string root = Path.Combine(Path.GetTempPath(), "dv-runner-http-" + Guid.NewGuid().ToString("N"));
        var result = SignedFeedUpdateRunner.Run(settings, Path.Combine(root, "sig"), Path.Combine(root, "state"), _ =>
        {
            factoryCalls++;
            throw new InvalidOperationException("HTTP must be rejected before transport construction");
        });

        Assert.Equal(SignedFeedRunResult.ExitNotConfigured, result.ExitCode);
        Assert.Equal(0, factoryCalls);
        Assert.False(Directory.Exists(root));
        Assert.Contains("URL HTTPS válida", result.Message);
    }

    [Fact]
    public void LegacyUnsignedUrl_IsClearedAndNeverMigratedIntoSignedTrust()
    {
        string root = NewRoot();
        string path = Path.Combine(root, "appsettings.json");
        try
        {
            File.WriteAllText(path, "{\"SchemaVersion\":1,\"SignatureUpdateUrl\":\"http://attacker.test/hashes.txt\"}");
            var settings = AppSettings.Load(path);

#pragma warning disable CS0618
            Assert.Equal(string.Empty, settings.SignatureUpdateUrl);
#pragma warning restore CS0618
            Assert.Equal(string.Empty, settings.SignedUpdateFeedUrl);
            Assert.False(settings.EnableHttpSignedUpdates);
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void ProductionAssembly_ContainsNoUnsignedUpdateManager()
    {
        Assert.Null(typeof(AppSettings).Assembly.GetType("DataVanger.Core.UpdateManager"));
    }

    private static AppSettings CompleteSettings(string publicPem) => new()
    {
        EnableHttpSignedUpdates = true,
        SignedUpdateFeedUrl = "https://updates.example.test/feed/manifest.json",
        SignedUpdateFeedId = FeedId,
        SignedUpdateKeyId = KeyId,
        SignedUpdateAlgorithm = SignedManifestVerifier.AlgorithmRsaPss,
        SignedUpdatePublicKeyPem = publicPem,
    };
}
