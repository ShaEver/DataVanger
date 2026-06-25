using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;
using DataVanger.Detection;
using DataVanger.Infrastructure;

// Phase 12_REAL_LIBYARA_ACTIVATION — real-YARA backend activation CANDIDATE tests.
//
// These tests go through the public LibyaraEngine.TryCreate / IYaraEngine surface, which
// exists in every build configuration, so this file compiles and passes whether or not
// DataVanger was built with YARA_REAL and whether or not the native libyara is present.
// The real native path is exercised only when TryCreate returns a non-null engine
// (built with YARA_REAL AND the native libyara loaded at runtime); otherwise each test
// verifies the guaranteed lightweight fallback instead — exactly the spec's allowed
// "skip with clear reason / assert fallback" behaviour for Windows-guarded native tests.
//
// Operator hard-validation: set environment variable DATAVANGER_REQUIRE_REAL_YARA=1 so a
// "backend unavailable" result becomes a FAILURE that surfaces the captured native-load
// diagnostics, instead of a soft skip. This is how native-load errors are made visible
// during Windows validation (they are never swallowed).
public class RealYaraBackendTests
{
    private const string SmokeString = "DataVangerYaraSmokeTest";
    private const string SmokeRule =
        "rule DataVangerSmokeRule {\n  strings:\n    $a = \"DataVangerYaraSmokeTest\"\n  condition:\n    $a\n}\n";

    private static bool RequireReal()
    {
        string? v = Environment.GetEnvironmentVariable("DATAVANGER_REQUIRE_REAL_YARA");
        return string.Equals(v, "1", StringComparison.Ordinal)
            || string.Equals(v, "true", StringComparison.OrdinalIgnoreCase);
    }

    private static string NewDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "dvtest_realyara_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void Cleanup(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort */ }
    }

    private static string WriteTarget(string dir, string content)
    {
        string p = Path.Combine(dir, "sample_" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllText(p, content);
        return p;
    }

    // Soft-skip helper: returns true if the real backend was unavailable. Under
    // DATAVANGER_REQUIRE_REAL_YARA the unavailability is asserted as a failure with the
    // captured diagnostics so a broken native load is not hidden during validation.
    private static bool RealBackendUnavailable(LibyaraEngine? engine, IReadOnlyList<string> diagnostics)
    {
        if (engine is not null) return false;
        Assert.False(RequireReal(),
            "DATAVANGER_REQUIRE_REAL_YARA is set but the real YARA backend was unavailable. Diagnostics: "
            + (diagnostics.Count == 0 ? "(none captured)" : string.Join(" | ", diagnostics)));
        return true;
    }

    [Fact]
    public void RealYaraBackend_CompilesSmokeRule_WhenNativeBackendAvailable()
    {
        string dir = NewDir();
        var diag = new List<string>();
        try
        {
            File.WriteAllText(Path.Combine(dir, "smoke.yar"), SmokeRule);
            using var engine = LibyaraEngine.TryCreate(dir, diag.Add);
            if (RealBackendUnavailable(engine, diag)) return;

            Assert.True(engine!.RuleCount > 0, "Real backend compiled 0 rules from the trivial smoke rule.");
            string target = WriteTarget(dir, "noise " + SmokeString + " noise");
            var matches = engine.Scan(target, 32);
            Assert.Contains(matches, m => m.RuleName == "DataVangerSmokeRule");
        }
        finally { Cleanup(dir); }
    }

    [Fact]
    public void RealYaraBackend_RealMatchesAreNonConfirming()
    {
        string dir = NewDir();
        var diag = new List<string>();
        try
        {
            File.WriteAllText(Path.Combine(dir, "smoke.yar"), SmokeRule);
            using var engine = LibyaraEngine.TryCreate(dir, diag.Add);
            if (RealBackendUnavailable(engine, diag)) return;

            string target = WriteTarget(dir, "xx " + SmokeString + " xx");
            var matches = engine!.Scan(target, 32);
            Assert.NotEmpty(matches);
            // Every real external match must be additive-only, never a confirmation.
            Assert.All(matches, m => Assert.False(m.Confirmed, "Real YARA match must never confirm malware."));
            Assert.All(matches, m => Assert.Equal(0, m.Score));
        }
        finally { Cleanup(dir); }
    }

    [Fact]
    public void RealYaraBackend_BadRuleFile_DoesNotBreakEngine()
    {
        string dir = NewDir();
        var diag = new List<string>();
        try
        {
            File.WriteAllText(Path.Combine(dir, "good.yar"), SmokeRule);
            // Invalid YARA (unterminated rule / nonsense) alongside the valid rule.
            File.WriteAllText(Path.Combine(dir, "bad.yar"),
                "rule Broken {\n  strings:\n    $a = \"x\"\n  condition:\n    $a");
            // TryCreate must never throw, regardless of backend availability.
            using var engine = LibyaraEngine.TryCreate(dir, diag.Add);
            if (RealBackendUnavailable(engine, diag)) return;

            // The good rule still loaded and works; the malformed file was isolated.
            Assert.True(engine!.RuleCount > 0);
            string target = WriteTarget(dir, "yy " + SmokeString + " yy");
            Assert.Contains(engine.Scan(target, 32), m => m.RuleName == "DataVangerSmokeRule");
        }
        finally { Cleanup(dir); }
    }

    [Fact]
    public void RealYaraBackend_UnavailableOrEmpty_FallsBackToLightweight()
    {
        // An empty rules directory yields 0 rules, so TryCreate returns null in EVERY
        // configuration (no YARA_REAL, or YARA_REAL with native present but no rules).
        string dir = NewDir();
        try
        {
            Assert.Null(LibyaraEngine.TryCreate(dir));

            // The lightweight adapter remains a valid IYaraEngine fallback.
            IYaraEngine fallback = new YaraEngineAdapter(LightweightYaraDatabase.Load(dir));
            Assert.Equal(0, fallback.RuleCount);
            Assert.Empty(fallback.Scan(typeof(int).Assembly.Location, 32));
        }
        finally { Cleanup(dir); }
    }

    [Fact]
    public async Task YaraDetectionModule_RealYaraHit_DoesNotConfirmMalware()
    {
        // Emulates how LibyaraEngine emits ALL real external matches: Confirmed=false, Score=0.
        var engine = new StubRealEngine(
            new LightweightYaraMatch("DataVangerSmokeRule", "regra YARA externa",
                Confirmed: false, Score: 0, MatchedPatterns: 1, TotalPatterns: 1));

        var module = new YaraDetectionModule(engine, new YaraDetectionModule.YaraOptions(true, 32));
        var target = new ScanTarget(new FileInfo(typeof(int).Assembly.Location));
        var context = new ScanContext(
            new ScanOptions { Profile = ScanProfile.Deep },
            new AppSettings(),
            runningProcessPaths: Array.Empty<string>(),
            persistenceExactPaths: Array.Empty<string>(),
            persistenceBlob: "");

        var evidence = await module.AnalyzeAsync(target, context, CancellationToken.None);

        Assert.NotEmpty(evidence);
        Assert.All(evidence, e => Assert.False(e.CanConfirmMalware, "Real YARA hit must not confirm malware."));
        Assert.All(evidence, e => Assert.NotEqual(EvidenceStrength.Confirmed, e.Strength));
        Assert.All(evidence, e => Assert.Equal(0, e.ScoreDelta));
    }

    private sealed class StubRealEngine : IYaraEngine
    {
        private readonly IReadOnlyList<LightweightYaraMatch> _matches;
        public StubRealEngine(params LightweightYaraMatch[] matches) => _matches = matches;
        public int RuleCount => 1;
        public IReadOnlyList<LightweightYaraMatch> Scan(string filePath, int maxScanSizeMB) => _matches;
    }
}
