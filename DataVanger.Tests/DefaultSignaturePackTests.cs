using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using DataVanger.Core;
using DataVanger.Core.Domain;
using DataVanger.Detection;
using DataVanger.Infrastructure;

namespace DataVanger.Tests;

// Proves the bundled default detection pack takes the scanner out of its "blind" state:
// it ships the EICAR test signature, seeds it idempotently into the user's signature root
// without clobbering user edits, and drives the confirm -> auto-quarantine gate end to end.
// Filter: ~DefaultSignaturePack.
public class DefaultSignaturePackTests
{
    // EICAR Standard Anti-Virus Test File, assembled at runtime so this source file does
    // not itself contain the contiguous 68-byte signature.
    private const string EicarPart1 = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STAND";
    private const string EicarPart2 = "ARD-ANTIVIRUS-TEST-FILE!$H+H*";
    private static string EicarText => EicarPart1 + EicarPart2;

    private const string EicarSha256 = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";

    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "dvtest_defpack_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static void Cleanup(string root)
    {
        try { Directory.Delete(root, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort */ }
    }

    private static string Sha256Hex(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)); // upper-case hex

    [Fact]
    public void EicarConstant_MatchesComputedHash()
    {
        Assert.Equal(EicarSha256, Sha256Hex(System.Text.Encoding.ASCII.GetBytes(EicarText)));
    }

    [Fact]
    public void ShippedDefaultPack_ContainsExactlyTheEicarHash()
    {
        // The pack copied next to the test assembly must contain the EICAR hash and nothing
        // else — catches any transcription error in the shipped known_malicious_sha256.txt.
        Assert.True(File.Exists(Path.Combine(DefaultSignaturePack.DefaultsRoot, DefaultSignaturePack.MaliciousFileName)),
            $"Default pack not copied to test output: {DefaultSignaturePack.DefaultsRoot}");

        var baseline = DefaultSignaturePack.BaselineMaliciousHashes();
        Assert.Single(baseline);
        Assert.Contains(EicarSha256, baseline);
    }

    [Fact]
    public void EnsureSeeded_PopulatesEmptyRoot_AndIsKnownMalicious()
    {
        var root = NewRoot();
        try
        {
            DefaultSignaturePack.EnsureSeeded(root);

            var db = SignatureDatabase.Load(root);
            Assert.True(db.IsKnownMalicious(EicarSha256), "EICAR hash must be known-malicious after seeding.");
            Assert.False(db.IsKnownSafe(EicarSha256));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void EnsureSeeded_IsIdempotent_NoDuplicateLines()
    {
        var root = NewRoot();
        try
        {
            DefaultSignaturePack.EnsureSeeded(root);
            DefaultSignaturePack.EnsureSeeded(root); // second run must not append again

            string file = Path.Combine(root, DefaultSignaturePack.MaliciousFileName);
            int occurrences = File.ReadLines(file)
                .Count(l => SignatureDatabase.ParseHashLine(l) == EicarSha256);
            Assert.Equal(1, occurrences);
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void EnsureSeeded_PreservesPreexistingUserEntries()
    {
        var root = NewRoot();
        try
        {
            string file = Path.Combine(root, DefaultSignaturePack.MaliciousFileName);
            string userHash = new string('A', 64);
            File.WriteAllText(file, "# user list\n" + userHash + "\n");

            DefaultSignaturePack.EnsureSeeded(root);

            var db = SignatureDatabase.Load(root);
            Assert.True(db.IsKnownMalicious(userHash), "Pre-existing user hash must be preserved.");
            Assert.True(db.IsKnownMalicious(EicarSha256), "EICAR baseline must be added alongside it.");
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public async Task SeededPack_DrivesConfirmedMalware_AndAutomaticAction()
    {
        var root = NewRoot();
        try
        {
            DefaultSignaturePack.EnsureSeeded(root);
            var db = SignatureDatabase.Load(root);

            // 1) The hash module — the only CanConfirmMalware source — confirms the EICAR hash.
            var module = new HashDetectionModule(new SignatureService(db));
            var target = new ScanTarget(new FileInfo(typeof(int).Assembly.Location)) { Sha256 = EicarSha256 };
            var context = new ScanContext(
                new ScanOptions { Profile = ScanProfile.Deep },
                new AppSettings(),
                runningProcessPaths: Array.Empty<string>(),
                persistenceExactPaths: Array.Empty<string>(),
                persistenceBlob: "");

            var evidence = await module.AnalyzeAsync(target, context, CancellationToken.None);
            Assert.Contains(evidence, e => e.CanConfirmMalware);
            Assert.True(target.IsKnownMalicious);
            Assert.Equal(FileTrustState.KnownMalicious, target.TrustState);

            // 2) The classification gate turns a known-malicious hash into ConfirmedMalware and
            //    authorizes automatic quarantine (mirrors how ScanEngine sets IsBlacklisted).
            var finding = new ScanFinding
            {
                Path = @"C:\Users\Test\Downloads\eicar.com",
                Score = RiskThresholds.Critical,
                IsBlacklisted = true,
            };
            Assert.Equal(ThreatClass.ConfirmedMalware, ThreatClassificationPolicy.Classify(finding));
            Assert.True(ThreatClassificationPolicy.AllowsAutomaticAction(finding));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void Describe_ReportsBaselineOnly_WhenOnlyEicarSeeded()
    {
        var root = NewRoot();
        try
        {
            DefaultSignaturePack.EnsureSeeded(root);
            var db = SignatureDatabase.Load(root);
            var status = DefaultSignaturePack.Describe(db, new LightweightYaraDatabase());

            Assert.False(status.IsBlind);
            Assert.True(status.IsBaselineOnly);
            Assert.True(status.KnownMalicious >= 1);
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void Describe_ReportsBlind_WhenNothingLoaded()
    {
        var status = DefaultSignaturePack.Describe(new SignatureDatabase(), new LightweightYaraDatabase());
        Assert.True(status.IsBlind);
        Assert.False(status.IsBaselineOnly);
    }
}
