using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;
using DataVanger.Core;
using DataVanger.Reputation;

// Phase 11 — opt-in certificate-aware publisher identity validation.
// These tests are pure/deterministic: normalization, thumbprint handling, mode logic, and
// FAIL-CLOSED behaviour for stronger modes. They do NOT require a trusted-rooted production
// certificate, network access, or real Authenticode — a self-signed cert deterministically
// fails chain validation (and ValidateChain also returns false off-Windows), which is exactly
// the fail-closed path under test. "Chain success -> trusted" remains pending Windows corpus
// validation (no trusted-rooted fixture available here). Filter: ~Publisher.
public class PublisherIdentityTests
{
    private static AppSettings Settings(PublisherValidationMode mode, string[]? trusted = null, string[]? thumbprints = null) =>
        new()
        {
            PublisherValidationMode = mode,
            TrustedPublishers = new List<string>(trusted ?? new[] { "Microsoft" }),
            ExtraTrustedPublishers = new List<string>(),
            TrustedPublisherThumbprints = new List<string>(thumbprints ?? Array.Empty<string>()),
        };

    private static X509Certificate2 MakeSelfSigned(string subjectCn)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={subjectCn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    // ── Normalization / name matching (pure) ─────────────────────────────────────

    [Fact]
    public void MatchesTrustedName_Matches_TrustedSubstring_NotUnrelated()
    {
        Assert.True(PublisherIdentity.MatchesTrustedName("CN=Microsoft Corporation, O=...", new[] { "Microsoft" }));
        Assert.False(PublisherIdentity.MatchesTrustedName("CN=Evil Corp", new[] { "Microsoft" }));
        Assert.False(PublisherIdentity.MatchesTrustedName(null, new[] { "Microsoft" }));
        Assert.False(PublisherIdentity.MatchesTrustedName("CN=Microsoft", null));
    }

    // ── Thumbprint normalization / comparison (pure) ─────────────────────────────

    [Fact]
    public void NormalizeThumbprint_AcceptsCommonFormattingDifferences()
    {
        Assert.Equal("ABCDEF", PublisherIdentity.NormalizeThumbprint("ab:cd ef"));
        Assert.Equal("ABCDEF", PublisherIdentity.NormalizeThumbprint("AB-CD-EF"));
        Assert.Equal("ABCD", PublisherIdentity.NormalizeThumbprint("0xABcd"));
    }

    [Fact]
    public void NormalizeThumbprint_Malformed_ReturnsEmpty()
    {
        Assert.Equal("", PublisherIdentity.NormalizeThumbprint(null));
        Assert.Equal("", PublisherIdentity.NormalizeThumbprint("   "));
        Assert.Equal("", PublisherIdentity.NormalizeThumbprint("XYZ123")); // X/Y/Z not hex
    }

    [Fact]
    public void MatchesConfiguredThumbprint_MatchAcrossFormatting_AndMismatch()
    {
        Assert.True(PublisherIdentity.MatchesConfiguredThumbprint("AABBCCDD", new[] { "aa:bb:cc:dd" }));
        Assert.False(PublisherIdentity.MatchesConfiguredThumbprint("AABBCCDD", new[] { "11223344" }));
    }

    [Fact]
    public void MatchesConfiguredThumbprint_EmptyOrMalformedConfig_NotTrusted()
    {
        Assert.False(PublisherIdentity.MatchesConfiguredThumbprint("AABBCCDD", Array.Empty<string>()));
        Assert.False(PublisherIdentity.MatchesConfiguredThumbprint("AABBCCDD", new[] { "ZZZZ" }));
        Assert.False(PublisherIdentity.MatchesConfiguredThumbprint("", new[] { "AABBCCDD" }));
    }

    // ── Default Substring mode preserves legacy behaviour (name-only, no certificate) ─

    [Fact]
    public void Substring_NameOnly_PreservesLegacyMatch_AndNeedsNoCertificate()
    {
        // Returning true from a name string alone proves Substring requires no chain/cert.
        Assert.True(PublisherIdentity.IsTrustedByName("CN=Microsoft Corporation", Settings(PublisherValidationMode.Substring, new[] { "Microsoft" })));
        Assert.False(PublisherIdentity.IsTrustedByName("CN=Evil Corp", Settings(PublisherValidationMode.Substring, new[] { "Microsoft" })));
    }

    [Fact]
    public void NullSettings_AreNotTrusted()
    {
        Assert.False(PublisherIdentity.IsTrustedByName("CN=Microsoft", null));
        Assert.False(PublisherIdentity.IsTrustedByCertificate(null, Settings(PublisherValidationMode.Substring)));
    }

    // ── Stronger modes on the name-only production path FAIL CLOSED ──────────────

    [Fact]
    public void StrongerModes_NameOnly_FailClosed_EvenWhenNameMatches()
    {
        Assert.False(PublisherIdentity.IsTrustedByName("CN=Microsoft Corporation", Settings(PublisherValidationMode.ChainAndName, new[] { "Microsoft" })));
        Assert.False(PublisherIdentity.IsTrustedByName("CN=Microsoft Corporation", Settings(PublisherValidationMode.ChainAndThumbprint, new[] { "Microsoft" })));
    }

    // ── Certificate-based evaluation (synthetic self-signed cert) ────────────────

    [Fact]
    public void ValidateChain_SelfSigned_IsNotTrusted()
    {
        using var cert = MakeSelfSigned("Microsoft Test");
        Assert.False(PublisherIdentity.ValidateChain(cert)); // untrusted root → fail closed (and false off-Windows)
    }

    [Fact]
    public void Substring_ByCertificate_UsesSubjectName_NoChainRequired()
    {
        using var cert = MakeSelfSigned("Microsoft Test");
        Assert.True(PublisherIdentity.IsTrustedByCertificate(cert, Settings(PublisherValidationMode.Substring, new[] { "Microsoft" })));
    }

    [Fact]
    public void ChainAndName_SelfSigned_FailsClosed_EvenIfNameMatches()
    {
        using var cert = MakeSelfSigned("Microsoft Test");
        Assert.False(PublisherIdentity.IsTrustedByCertificate(cert, Settings(PublisherValidationMode.ChainAndName, new[] { "Microsoft" })));
    }

    [Fact]
    public void ChainAndThumbprint_SelfSigned_FailsClosed_EvenIfThumbprintConfigured()
    {
        using var cert = MakeSelfSigned("Microsoft Test");
        var s = Settings(PublisherValidationMode.ChainAndThumbprint, new[] { "Microsoft" }, new[] { cert.Thumbprint });
        // Thumbprint matches, but the self-signed chain does not validate → not trusted.
        Assert.False(PublisherIdentity.IsTrustedByCertificate(cert, s));
    }

    [Fact]
    public void ChainAndThumbprint_EmptyThumbprintConfig_NotTrusted()
    {
        using var cert = MakeSelfSigned("Microsoft Test");
        Assert.False(PublisherIdentity.IsTrustedByCertificate(cert, Settings(PublisherValidationMode.ChainAndThumbprint, new[] { "Microsoft" }, Array.Empty<string>())));
    }

    // ── Malware precedence preserved through the routed evaluator (default mode) ──

    [Fact]
    public void KnownMalicious_OverridesTrustedPublisher_AfterRouting()
    {
        var engine = new ReputationEngine(new SignatureDatabase(), new AppSettings()); // default Substring
        var eval = engine.Evaluate(new ReputationSubject
        {
            Sha256 = new string('2', 64),
            Path = @"C:\Users\T\Downloads\payload.exe",
            Extension = ".exe",
            BaseScore = 1,
            IsKnownMalicious = true,
            HasConfirmedEvidence = true,
            IsSigned = true,
            Publisher = "Microsoft Corporation", // a "trusted" signer must NOT rescue a known-malicious hash
            LastWriteUtc = DateTime.UtcNow,
        }, null);

        Assert.Equal(ReputationTrustState.KnownBad, eval.TrustState);
        Assert.Contains(eval.Evidence, e => e.CanConfirmMalware);
    }
}
