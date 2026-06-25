using System;
using System.IO;
using System.Threading;
using DataVanger.Core;
using DataVanger.Infrastructure;

// Performance fix — catalog-probe gating + persistent signature-trust cache.
// Verifies: VerifySignature skips the expensive catalog probe when allowCatalog is
// false (non-system files); the trust cache returns a stored result for an unchanged
// (path,mtime,size)+fingerprint and misses on any change; embedded verification is
// unaffected. Filters: ~Signature, ~Catalog, ~Scan.
public class SignatureTrustCacheTests
{
    private static void ResetSeams()
    {
        WinTrust.EmbeddedProbeOverride = null;
        WinTrust.EmbeddedSubjectOverride = null;
        WinTrust.CatalogProbeOverride = null;
    }

    [Xunit.Fact]
    public void VerifySignature_AllowCatalogFalse_SkipsCatalogProbe()
    {
        try
        {
            WinTrust.EmbeddedProbeOverride = _ => false; // no embedded signature
            WinTrust.CatalogProbeOverride = _ => new SignatureVerificationResult
            { IsSigned = true, Source = SignatureSource.Catalog, SignerSubject = "CN=Microsoft Windows" };

            // System path (allowed): catalog probe is consulted -> signed.
            Xunit.Assert.True(WinTrust.VerifySignature(@"C:\Windows\System32\x.dll", allowCatalog: true).IsSigned);
            // Non-system path (not allowed): catalog probe is skipped -> unsigned.
            Xunit.Assert.False(WinTrust.VerifySignature(@"C:\Users\me\AppData\Local\App\app.dll", allowCatalog: false).IsSigned);
        }
        finally { ResetSeams(); }
    }

    [Xunit.Fact]
    public void VerifySignature_AllowCatalogFalse_KeepsEmbeddedVerification()
    {
        try
        {
            WinTrust.EmbeddedProbeOverride = _ => true; // embedded signature present
            WinTrust.EmbeddedSubjectOverride = _ => "CN=Contoso";
            WinTrust.CatalogProbeOverride = _ => throw new InvalidOperationException("catalog must not be reached");

            var r = WinTrust.VerifySignature(@"C:\Users\me\app.exe", allowCatalog: false);

            Xunit.Assert.True(r.IsSigned);
            Xunit.Assert.Equal(SignatureSource.Embedded, r.Source);
            Xunit.Assert.Equal("CN=Contoso", r.SignerSubject);
        }
        finally { ResetSeams(); }
    }

    [Xunit.Fact]
    public void TrustCache_Hit_OnUnchanged_Miss_OnFingerprintOrContentChange()
    {
        string dir = Directory.CreateTempSubdirectory("dv_trust_").FullName;
        string cachePath = Path.Combine(dir, "trust_cache.json");
        string filePath = Path.Combine(dir, "a.dll");
        try
        {
            File.WriteAllText(filePath, "hello");
            var cache = new SignatureTrustCache(cachePath);
            var file = new FileInfo(filePath);

            Xunit.Assert.False(cache.TryGet(file, "fpA", out _)); // empty cache

            cache.Store(file, "fpA", new SignatureVerificationResult
            { IsSigned = true, SignerSubject = "CN=Vendor", Source = SignatureSource.Embedded });
            file.Refresh();

            Xunit.Assert.True(cache.TryGet(file, "fpA", out var got));
            Xunit.Assert.True(got.IsSigned);
            Xunit.Assert.Equal("CN=Vendor", got.SignerSubject);
            Xunit.Assert.Equal(SignatureSource.Embedded, got.Source);

            Xunit.Assert.False(cache.TryGet(file, "fpB", out _)); // fingerprint change -> miss

            Thread.Sleep(10);
            File.WriteAllText(filePath, "hello world (changed)");
            Xunit.Assert.False(cache.TryGet(new FileInfo(filePath), "fpA", out _)); // content change -> miss
        }
        finally { Directory.Delete(dir, true); }
    }

    [Xunit.Fact]
    public void TrustCache_SurvivesPersistAndReload()
    {
        string dir = Directory.CreateTempSubdirectory("dv_trust2_").FullName;
        string cachePath = Path.Combine(dir, "trust_cache.json");
        string filePath = Path.Combine(dir, "b.dll");
        try
        {
            File.WriteAllText(filePath, "stable content");
            var file = new FileInfo(filePath);

            var cache = new SignatureTrustCache(cachePath);
            cache.Store(file, "fp1", new SignatureVerificationResult
            { IsSigned = true, SignerSubject = "CN=Catalog Signer", Source = SignatureSource.Catalog });
            cache.Persist();

            var reloaded = new SignatureTrustCache(cachePath);
            Xunit.Assert.True(reloaded.TryGet(new FileInfo(filePath), "fp1", out var got));
            Xunit.Assert.Equal(SignatureSource.Catalog, got.Source);
            Xunit.Assert.Equal("CN=Catalog Signer", got.SignerSubject);
        }
        finally { Directory.Delete(dir, true); }
    }
}
