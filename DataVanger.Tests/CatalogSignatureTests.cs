using System;
using System.IO;
using DataVanger.Core;

// BETA 11A — catalog-aware signature verification.
// Unit tests drive WinTrust.VerifySignature deterministically via the embedded/
// catalog test seams (no native calls, no real signed files). Integration smoke
// tests are guarded for Windows. The invariants asserted: embedded is tried first;
// a catalog match only grants "signed" on a real catalog success; any failure
// yields Unsigned (never fabricated trust); and a catalog signer flows through the
// existing, unchanged trusted-publisher path.
// Filters: ~Signature, ~Catalog, ~Publisher, ~AntiFalsePositive.
public class CatalogSignatureTests
{
    private static void ResetSeams()
    {
        WinTrust.EmbeddedProbeOverride = null;
        WinTrust.EmbeddedSubjectOverride = null;
        WinTrust.CatalogProbeOverride = null;
    }

    [Xunit.Fact]
    public void VerifySignature_EmbeddedValid_TakesPrecedenceOverCatalog()
    {
        try
        {
            WinTrust.EmbeddedProbeOverride = _ => true;
            WinTrust.EmbeddedSubjectOverride = _ => "CN=Embedded Publisher";
            WinTrust.CatalogProbeOverride = _ => new SignatureVerificationResult
            { IsSigned = true, SignerSubject = "CN=Catalog Signer", Source = SignatureSource.Catalog };

            var r = WinTrust.VerifySignature(@"C:\x\a.dll");

            Xunit.Assert.True(r.IsSigned);
            Xunit.Assert.Equal(SignatureSource.Embedded, r.Source);
            Xunit.Assert.Equal("CN=Embedded Publisher", r.SignerSubject);
        }
        finally { ResetSeams(); }
    }

    [Xunit.Fact]
    public void VerifySignature_EmbeddedInvalid_FallsBackToCatalog()
    {
        try
        {
            WinTrust.EmbeddedProbeOverride = _ => false;
            WinTrust.CatalogProbeOverride = _ => new SignatureVerificationResult
            { IsSigned = true, SignerSubject = "CN=Microsoft Windows, O=Microsoft Corporation", Source = SignatureSource.Catalog };

            var r = WinTrust.VerifySignature(@"C:\Windows\System32\kerberos.dll");

            Xunit.Assert.True(r.IsSigned);
            Xunit.Assert.Equal(SignatureSource.Catalog, r.Source);
            Xunit.Assert.Contains("Microsoft", r.SignerSubject, StringComparison.OrdinalIgnoreCase);
        }
        finally { ResetSeams(); }
    }

    [Xunit.Fact]
    public void VerifySignature_BothFail_IsUnsigned()
    {
        try
        {
            WinTrust.EmbeddedProbeOverride = _ => false;
            WinTrust.CatalogProbeOverride = _ => SignatureVerificationResult.Unsigned;

            var r = WinTrust.VerifySignature(@"C:\Users\me\evil.exe");

            Xunit.Assert.False(r.IsSigned);
            Xunit.Assert.Equal(SignatureSource.None, r.Source);
            Xunit.Assert.Equal("", r.SignerSubject);
        }
        finally { ResetSeams(); }
    }

    [Xunit.Fact]
    public void VerifySignature_CatalogProbeThrows_DoesNotCreateTrust()
    {
        try
        {
            WinTrust.EmbeddedProbeOverride = _ => false;
            WinTrust.CatalogProbeOverride = _ => throw new InvalidOperationException("native failure");

            var r = WinTrust.VerifySignature(@"C:\Users\me\thing.dll");

            Xunit.Assert.False(r.IsSigned);
            Xunit.Assert.Equal(SignatureSource.None, r.Source);
        }
        finally { ResetSeams(); }
    }

    [Xunit.Fact]
    public void VerifySignature_CatalogReportsNotSigned_IsUnsigned()
    {
        try
        {
            WinTrust.EmbeddedProbeOverride = _ => false;
            // A catalog lookup that did not verify must not be treated as signed.
            WinTrust.CatalogProbeOverride = _ => new SignatureVerificationResult
            { IsSigned = false, SignerSubject = "", Source = SignatureSource.None };

            var r = WinTrust.VerifySignature(@"C:\Users\me\unsigned.dll");

            Xunit.Assert.False(r.IsSigned);
        }
        finally { ResetSeams(); }
    }

    [Xunit.Fact]
    public void VerifySignature_EmbeddedProbeThrows_FallsBackThenUnsigned()
    {
        try
        {
            WinTrust.EmbeddedProbeOverride = _ => throw new InvalidOperationException("embedded boom");
            WinTrust.CatalogProbeOverride = _ => SignatureVerificationResult.Unsigned;

            var r = WinTrust.VerifySignature(@"C:\x\y.dll");

            Xunit.Assert.False(r.IsSigned); // embedded exception must not crash or create trust
        }
        finally { ResetSeams(); }
    }

    [Xunit.Fact]
    public void VerifySignature_BlankPath_IsUnsigned()
    {
        Xunit.Assert.False(WinTrust.VerifySignature("").IsSigned);
        Xunit.Assert.False(WinTrust.VerifySignature("   ").IsSigned);
    }

    [Xunit.Fact]
    public void CatalogSignerSubject_FlowsThroughExistingTrustedPublisherPath()
    {
        // A catalog signer subject (e.g. Microsoft) must be trusted by the SAME,
        // unchanged publisher path the engine already uses for embedded signers.
        var settings = new AppSettings(); // default Substring mode, includes "Microsoft"
        Xunit.Assert.True(PublisherIdentity.IsTrustedByName(
            "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US", settings));
    }

    [Xunit.Fact]
    public void SignatureAlone_DoesNotTrustArbitraryPublisher()
    {
        // Catalog/embedded signing surfaces a signer; trust still requires the signer
        // to match the trusted list. An unknown vendor is NOT trusted just by signing.
        var settings = new AppSettings();
        Xunit.Assert.False(PublisherIdentity.IsTrustedByName("CN=Totally Unknown Vendor LLC", settings));
    }

    // ── Windows-guarded integration smoke (skipped on non-Windows / no-SDK hosts) ──

    [Xunit.Fact]
    public void Integration_System32Component_VerifiesAsSigned_OnWindows()
    {
        if (!OperatingSystem.IsWindows()) return;
        string dll = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");
        if (!File.Exists(dll)) return;

        var r = WinTrust.VerifySignature(dll);

        Xunit.Assert.True(r.IsSigned, "A core System32 component must verify as signed (embedded or catalog).");
        Xunit.Assert.NotEqual(SignatureSource.None, r.Source);
    }

    [Xunit.Fact]
    public void Integration_UnsignedTempFile_IsNotSigned_OnWindows()
    {
        if (!OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("dv_sig_").FullName;
        string path = Path.Combine(dir, "plain.bin");
        try
        {
            File.WriteAllText(path, "not a signed binary");
            var r = WinTrust.VerifySignature(path);
            Xunit.Assert.False(r.IsSigned);
        }
        finally { Directory.Delete(dir, true); }
    }
}
