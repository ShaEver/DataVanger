using System;
using System.IO;
using System.Linq;
using Xunit;
using DataVanger.Core;
using DataVanger.Core.Domain;
using DataVanger.Reputation;

// Phase 06 (Part A) — configurable Trusted Publishers.
// Verifies the centralised AppSettings.TrustedPublishers policy and that a
// trusted publisher never overrides a known-malicious hash. Pure/observable
// behaviour only; no production visibility was changed for these tests.
public class TrustedPublisherSettingsTests
{
    private static bool ContainsCi(System.Collections.Generic.IEnumerable<string> list, string needle) =>
        list.Any(p => p.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0);

    [Fact]
    public void Default_TrustedPublishers_ExcludeOpenAiWondershareSweetLabs()
    {
        var settings = new AppSettings();
        Assert.False(ContainsCi(settings.TrustedPublishers, "OpenAI"),
            "OpenAI must not be a default trusted publisher.");
        Assert.False(ContainsCi(settings.TrustedPublishers, "Wondershare"),
            "Wondershare must not be a default trusted publisher.");
        Assert.False(ContainsCi(settings.TrustedPublishers, "SweetLabs"),
            "SweetLabs must not be a default trusted publisher.");
    }

    [Fact]
    public void Default_TrustedPublishers_IncludeKnownSafeVendors()
    {
        var settings = new AppSettings();
        Assert.True(ContainsCi(settings.TrustedPublishers, "Microsoft"));
        Assert.True(ContainsCi(settings.TrustedPublishers, "Adobe"));
        Assert.NotEmpty(settings.TrustedPublishers);
    }

    [Fact]
    public void TrustedPublisherLists_SurviveSaveLoadRoundTrip_AndRemainUserEditable()
    {
        string path = Path.Combine(Path.GetTempPath(), "dvtest_settings_" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var settings = new AppSettings();
            settings.ExtraTrustedPublishers.Add("Contoso Signing Ltda");
            settings.Save(path);

            var loaded = AppSettings.Load(path);
            Assert.True(ContainsCi(loaded.TrustedPublishers, "Microsoft"),
                "Base trusted publishers must persist across save/load.");
            Assert.Contains("Contoso Signing Ltda", loaded.ExtraTrustedPublishers);
            Assert.False(ContainsCi(loaded.TrustedPublishers, "OpenAI"),
                "Unsafe vendors must not appear after round-trip.");
        }
        finally
        {
            try { File.Delete(path); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort cleanup */ }
        }
    }

    [Fact]
    public void ReputationEngine_TrustedPublisher_DoesNotOverrideKnownMaliciousHash()
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
            Publisher = "Microsoft Corporation", // trusted publisher must NOT rescue a malicious hash
            LastWriteUtc = DateTime.UtcNow,
        }, null);

        Assert.Equal(ReputationTrustState.KnownBad, eval.TrustState);
        Assert.Contains(eval.Evidence, e => e.CanConfirmMalware);
    }
}
