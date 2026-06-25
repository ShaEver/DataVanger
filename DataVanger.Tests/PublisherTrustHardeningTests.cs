using System;
using System.Collections.Generic;
using DataVanger.Core;
using DataVanger.Reputation;

// BETA 11D — publisher trust hardening: graduated trust states, spoof-resistant
// anchored matching, catalog-signer integration, and invalid-vs-unsigned distinction.
// Invariants asserted: a trusted name must START an RDN component (substring spoofing
// fails); valid signature is relief not proof of safety; trusted publisher is not
// immunity (confirmed malware overrides); invalid signatures get no valid-signature
// relief. Filters: ~Publisher, ~Reputation, ~AntiFalsePositive, ~Signature.
public class PublisherTrustHardeningTests
{
    private static AppSettings TrustMicrosoft() => new()
    {
        PublisherValidationMode = PublisherValidationMode.Substring,
        TrustedPublishers = new List<string> { "Microsoft" },
        ExtraTrustedPublishers = new List<string>(),
    };

    // ── Anchored, spoof-resistant matching ──

    [Xunit.Theory]
    [Xunit.InlineData("CN=Microsoft Corporation, O=Microsoft Corporation, C=US", true)]
    [Xunit.InlineData("Microsoft Windows", true)]
    [Xunit.InlineData("CN=Microsoft", true)]
    [Xunit.InlineData("CN=Evil Microsoft Corp", false)]   // name not at component start
    [Xunit.InlineData("CN=Microsofty Ltd", false)]        // not a boundary
    [Xunit.InlineData("CN=Not Microsoft At All", false)]  // substring-anywhere must fail
    [Xunit.InlineData("CN=Contoso", false)]
    public void AnchoredMatch_TrustsOnlyComponentStart(string subject, bool expected)
    {
        Xunit.Assert.Equal(expected, PublisherIdentity.MatchesTrustedNameAnchored(subject, new[] { "Microsoft" }));
    }

    [Xunit.Fact]
    public void AnchoredMatch_RejectsPunctuationSpoof_AcceptsRealComma()
    {
        Xunit.Assert.False(PublisherIdentity.MatchesTrustedNameAnchored("CN=Anthropic-Evil", new[] { "Anthropic" }));
        Xunit.Assert.True(PublisherIdentity.MatchesTrustedNameAnchored("CN=Anthropic, PBC", new[] { "Anthropic" }));
    }

    [Xunit.Fact]
    public void IsTrustedPublisherName_SubstringUsesAnchored_StrongerModesFailClosed_NullSafe()
    {
        Xunit.Assert.True(PublisherIdentity.IsTrustedPublisherName("CN=Microsoft Corporation", TrustMicrosoft()));
        Xunit.Assert.False(PublisherIdentity.IsTrustedPublisherName("CN=Evil Microsoft Corp", TrustMicrosoft()));

        var chain = TrustMicrosoft();
        chain.PublisherValidationMode = PublisherValidationMode.ChainAndName;
        Xunit.Assert.False(PublisherIdentity.IsTrustedPublisherName("CN=Microsoft Corporation", chain));
        Xunit.Assert.False(PublisherIdentity.IsTrustedPublisherName("CN=Microsoft", null));
    }

    // ── Graduated trust levels ──

    [Xunit.Fact]
    public void Evaluate_Unsigned()
    {
        Xunit.Assert.Equal(PublisherTrustLevel.Unsigned, PublisherIdentity.EvaluatePublisherTrust(SignatureVerificationResult.Unsigned, TrustMicrosoft()));
        Xunit.Assert.Equal(PublisherTrustLevel.Unsigned, PublisherIdentity.EvaluatePublisherTrust(null, TrustMicrosoft()));
    }

    [Xunit.Fact]
    public void Evaluate_Invalid_GetsNoValidRelief()
    {
        var r = new SignatureVerificationResult { IsSigned = false, SignaturePresentButUnverified = true };
        Xunit.Assert.Equal(PublisherTrustLevel.Invalid, PublisherIdentity.EvaluatePublisherTrust(r, TrustMicrosoft()));
    }

    [Xunit.Fact]
    public void Evaluate_ValidUntrusted()
    {
        var r = new SignatureVerificationResult { IsSigned = true, SignerSubject = "CN=Contoso Ltd", Source = SignatureSource.Embedded };
        Xunit.Assert.Equal(PublisherTrustLevel.Valid, PublisherIdentity.EvaluatePublisherTrust(r, TrustMicrosoft()));
    }

    [Xunit.Fact]
    public void Evaluate_Trusted_Embedded()
    {
        var r = new SignatureVerificationResult { IsSigned = true, SignerSubject = "CN=Microsoft Corporation", Source = SignatureSource.Embedded };
        Xunit.Assert.Equal(PublisherTrustLevel.Trusted, PublisherIdentity.EvaluatePublisherTrust(r, TrustMicrosoft()));
    }

    [Xunit.Fact]
    public void Evaluate_TrustedWindowsComponent_CatalogMicrosoft()
    {
        var r = new SignatureVerificationResult { IsSigned = true, SignerSubject = "CN=Microsoft Windows, O=Microsoft Corporation", Source = SignatureSource.Catalog };
        Xunit.Assert.Equal(PublisherTrustLevel.TrustedWindowsComponent, PublisherIdentity.EvaluatePublisherTrust(r, TrustMicrosoft()));
    }

    [Xunit.Fact]
    public void Evaluate_SpoofedTrustedName_IsOnlyValid_NotTrusted()
    {
        // A spoofed signer name (valid signature, but name not anchored) gets the measured
        // valid-untrusted relief, NOT trusted relief or immunity.
        var r = new SignatureVerificationResult { IsSigned = true, SignerSubject = "CN=Evil Microsoft Corp", Source = SignatureSource.Embedded };
        Xunit.Assert.Equal(PublisherTrustLevel.Valid, PublisherIdentity.EvaluatePublisherTrust(r, TrustMicrosoft()));
    }

    // ── WinTrust invalid-vs-unsigned distinction (seams) ──

    [Xunit.Fact]
    public void VerifySignature_PresentButInvalid_IsFlagged_AndMapsToInvalid()
    {
        try
        {
            WinTrust.EmbeddedProbeOverride = _ => false;             // signature does not verify
            WinTrust.EmbeddedSubjectOverride = _ => "CN=SomeVendor"; // but a cert blob is present
            WinTrust.CatalogProbeOverride = _ => SignatureVerificationResult.Unsigned;

            var r = WinTrust.VerifySignature(@"C:\x\bad.dll");

            Xunit.Assert.False(r.IsSigned);
            Xunit.Assert.True(r.SignaturePresentButUnverified);
            Xunit.Assert.Equal(PublisherTrustLevel.Invalid, PublisherIdentity.EvaluatePublisherTrust(r, TrustMicrosoft()));
        }
        finally { ResetSeams(); }
    }

    [Xunit.Fact]
    public void VerifySignature_TrulyUnsigned_NotFlaggedInvalid()
    {
        try
        {
            WinTrust.EmbeddedProbeOverride = _ => false;
            WinTrust.EmbeddedSubjectOverride = _ => ""; // no cert blob present
            WinTrust.CatalogProbeOverride = _ => SignatureVerificationResult.Unsigned;

            var r = WinTrust.VerifySignature(@"C:\x\plain.bin");

            Xunit.Assert.False(r.IsSigned);
            Xunit.Assert.False(r.SignaturePresentButUnverified);
        }
        finally { ResetSeams(); }
    }

    // ── Default trusted-publisher list changes ──

    [Xunit.Fact]
    public void DefaultTrustedPublishers_IncludeAnthropic_StillExcludeOpenAi_AndSpoofResistant()
    {
        var s = new AppSettings();
        Xunit.Assert.Contains(s.TrustedPublishers, p => p.Equals("Anthropic", StringComparison.OrdinalIgnoreCase));
        Xunit.Assert.DoesNotContain(s.TrustedPublishers, p => p.IndexOf("OpenAI", StringComparison.OrdinalIgnoreCase) >= 0);

        Xunit.Assert.True(PublisherIdentity.IsTrustedPublisherName("CN=\"Anthropic, PBC\", O=\"Anthropic, PBC\"", s));
        Xunit.Assert.False(PublisherIdentity.IsTrustedPublisherName("CN=Definitely Not Anthropic Inc", s));
        Xunit.Assert.False(PublisherIdentity.IsTrustedPublisherName("CN=Anthropics United", s));
    }

    // ── Trusted publisher is relief, NOT immunity ──

    [Xunit.Fact]
    public void TrustedPublisher_DoesNotRescue_KnownMaliciousHash()
    {
        var engine = new ReputationEngine(new SignatureDatabase(), new AppSettings());
        var eval = engine.Evaluate(new ReputationSubject
        {
            Sha256 = new string('2', 64),
            Path = @"C:\Users\T\Downloads\payload.exe",
            Extension = ".exe",
            BaseScore = 1,
            IsKnownMalicious = true,
            HasConfirmedEvidence = true,
            IsSigned = true,
            Publisher = "Microsoft Corporation",
            LastWriteUtc = DateTime.UtcNow,
        }, null);

        Xunit.Assert.Equal(ReputationTrustState.KnownBad, eval.TrustState);
    }

    [Xunit.Fact]
    public void SpoofedPublisher_DoesNotGetTrustedSignerRelief()
    {
        var engine = new ReputationEngine(new SignatureDatabase(), new AppSettings());
        var eval = engine.Evaluate(new ReputationSubject
        {
            Sha256 = new string('3', 64),
            Path = @"C:\Users\T\Downloads\app.exe",
            Extension = ".exe",
            BaseScore = 10,
            IsSigned = true,
            Publisher = "CN=Evil Microsoft Corp", // spoofed: not anchored
            LastWriteUtc = DateTime.UtcNow,
        }, null);

        Xunit.Assert.NotEqual("TrustedSigner", eval.SignerStatus);
    }

    private static void ResetSeams()
    {
        WinTrust.EmbeddedProbeOverride = null;
        WinTrust.EmbeddedSubjectOverride = null;
        WinTrust.CatalogProbeOverride = null;
    }
}
