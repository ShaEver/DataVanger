using System;
using System.IO;
using System.Threading;
using DataVanger.Core;
using DataVanger.Infrastructure;

// Catalog-probe gating and signature-observation safety. Verification always comes
// from the current file; persisted observations expose no lookup API. Filters:
// ~Signature, ~Catalog, ~Scan.
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
    public void SignatureObservation_CorruptJson_IsDiscardedAndReported()
    {
        string dir = Directory.CreateTempSubdirectory("dv_trust_").FullName;
        string cachePath = Path.Combine(dir, "trust_cache.json");
        string filePath = Path.Combine(dir, "a.dll");
        try
        {
            File.WriteAllText(cachePath, "{ invalid");
            var cache = new SignatureTrustCache(cachePath);
            Xunit.Assert.True(cache.Health.IsDegraded);
            Xunit.Assert.Equal("load-failed", cache.Health.Reason);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Xunit.Fact]
    public void SignatureObservation_PersistsNoSignatureVerdictOrCertificate()
    {
        string dir = Directory.CreateTempSubdirectory("dv_trust2_").FullName;
        string cachePath = Path.Combine(dir, "trust_cache.json");
        string filePath = Path.Combine(dir, "b.dll");
        try
        {
            File.WriteAllText(filePath, "stable content");
            var file = new FileInfo(filePath);

            var cache = new SignatureTrustCache(cachePath);
            cache.Observe(file, new SignatureVerificationResult
            {
                IsSigned = true,
                SignerSubject = "CN=Catalog Signer",
                Source = SignatureSource.Catalog,
                SignerCertificateRawData = new byte[] { 1, 2, 3, 4 },
            });
            cache.Persist();

            string persisted = File.ReadAllText(cachePath);
            Xunit.Assert.DoesNotContain("SignerSubject", persisted);
            Xunit.Assert.DoesNotContain("SignerCertificate", persisted);
            Xunit.Assert.DoesNotContain("IsSigned", persisted);
        }
        finally { Directory.Delete(dir, true); }
    }
}
