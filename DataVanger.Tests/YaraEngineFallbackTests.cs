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

// Phase 06 (Part B) — real YARA backend with graceful LightweightYaraDatabase fallback.
// Verifies: the optional real backend degrades to the lightweight fallback when not
// compiled in; real-style external matches never confirm malware; curated lightweight
// confirmed rules still confirm; and a missing rules directory is non-fatal.
public class YaraEngineFallbackTests
{
    // Simulates an IYaraEngine that produces matches (e.g. LibyaraEngine or the
    // lightweight DB) so the module's evidence mapping can be exercised directly.
    private sealed class StubYaraEngine : IYaraEngine
    {
        private readonly IReadOnlyList<LightweightYaraMatch> _matches;
        public StubYaraEngine(params LightweightYaraMatch[] matches) => _matches = matches;
        public int RuleCount => 1;
        public IReadOnlyList<LightweightYaraMatch> Scan(string filePath, int maxScanSizeMB) => _matches;
    }

    private static ScanContext NewContext() => new ScanContext(
        new ScanOptions { Profile = ScanProfile.Deep },
        new AppSettings(),
        runningProcessPaths: Array.Empty<string>(),
        persistenceExactPaths: Array.Empty<string>(),
        persistenceBlob: "");

    private static async Task<IReadOnlyList<Evidence>> RunModule(IYaraEngine engine)
    {
        var module = new YaraDetectionModule(engine, new YaraDetectionModule.YaraOptions(true, 32));
        var target = new ScanTarget(new FileInfo(typeof(int).Assembly.Location));
        return await module.AnalyzeAsync(target, NewContext(), CancellationToken.None);
    }

    [Fact]
    public void LibyaraEngine_TryCreate_WithoutRealPackage_ReturnsNullSoFallbackIsUsed()
    {
        string dir = Path.Combine(Path.GetTempPath(), "dvtest_libyara_" + Guid.NewGuid().ToString("N"));
        // In the default build (no YARA_REAL + no dnYara package) the real backend
        // is unavailable; TryCreate must return null so callers keep the fallback.
        Assert.Null(LibyaraEngine.TryCreate(dir));
    }

    [Fact]
    public async Task YaraDetectionModule_ExternalStyleMatch_IsNotConfirmedMalware()
    {
        // A non-confirmed match (how LibyaraEngine emits ALL real external matches).
        var engine = new StubYaraEngine(
            new LightweightYaraMatch("ext_rule", "regra YARA externa", Confirmed: false, Score: 0, MatchedPatterns: 1, TotalPatterns: 1));

        var evidence = await RunModule(engine);

        Assert.NotEmpty(evidence);
        Assert.All(evidence, e => Assert.False(e.CanConfirmMalware, "Real external YARA match must not confirm malware."));
        Assert.All(evidence, e => Assert.NotEqual(EvidenceStrength.Confirmed, e.Strength));
    }

    [Fact]
    public async Task YaraDetectionModule_ConfirmedLightweightRule_StillConfirms()
    {
        // Curated lightweight rules may still confirm — existing behaviour preserved.
        var engine = new StubYaraEngine(
            new LightweightYaraMatch("curated_rule", "regra confirmada", Confirmed: true, Score: 50, MatchedPatterns: 1, TotalPatterns: 1));

        var evidence = await RunModule(engine);

        Assert.Contains(evidence, e => e.CanConfirmMalware && e.Strength == EvidenceStrength.Confirmed);
    }

    [Fact]
    public void LightweightYaraDatabase_MissingRulesDirectory_DegradesGracefully()
    {
        string root = Path.Combine(Path.GetTempPath(), "dvtest_yara_" + Guid.NewGuid().ToString("N"));
        try
        {
            var db = LightweightYaraDatabase.Load(root); // must not throw on a fresh/empty root
            Assert.Equal(0, db.Count);
            Assert.Empty(db.ScanFile(typeof(int).Assembly.Location, 32));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort cleanup */ }
        }
    }
}
