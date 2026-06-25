using System;
using System.IO;
using System.Linq;
using Xunit;
using DataVanger.Core;

// Phase 13 — bounded, offline local YARA rule-pack loading & validation.
// All fixtures are created in temp directories: no network, no external rule packs, no native
// libyara (the real engine is inactive/scaffolded). Tests prove malformed/unsupported/oversized
// packs degrade gracefully with accurate counts, skipped rules never match, and confirmation
// semantics are unchanged. Filter: ~Yara.
public class YaraRulePackTests
{
    private const string ValidR1 =
        "rule R1 {\n  strings:\n    $a = \"ALPHA123\"\n    $b = \"BETA4567\"\n  condition:\n    all of them\n}\n";

    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "dvtest_yararp_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "yara_rules"));
        return root;
    }

    private static void WriteRule(string root, string fileName, string content) =>
        File.WriteAllText(Path.Combine(root, "yara_rules", fileName), content);

    private static string WriteTarget(string root, string content)
    {
        var p = Path.Combine(root, "target_" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllText(p, content);
        return p;
    }

    private static void Cleanup(string root)
    {
        try { Directory.Delete(root, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort */ }
    }

    [Fact]
    public void MissingDirectory_IsCreated_AndLoadsZero_NoThrow()
    {
        var root = Path.Combine(Path.GetTempPath(), "dvtest_yararp_missing_" + Guid.NewGuid().ToString("N"));
        try
        {
            var db = LightweightYaraDatabase.Load(root); // no yara_rules dir yet
            Assert.Equal(0, db.Count);
            Assert.Equal(0, db.Validation.LoadedRuleCount);
            Assert.True(Directory.Exists(Path.Combine(root, "yara_rules")));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void EmptyDirectory_LoadsZero_NoThrow()
    {
        var root = NewRoot();
        try
        {
            var db = LightweightYaraDatabase.Load(root, RulePackLimits.Default);
            Assert.Equal(0, db.Count);
            Assert.Equal(0, db.Validation.LoadedRuleCount);
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void ValidRule_Loads_AndMatches()
    {
        var root = NewRoot();
        try
        {
            WriteRule(root, "r1.yar", ValidR1);
            var db = LightweightYaraDatabase.Load(root, RulePackLimits.Default);
            Assert.Equal(1, db.Validation.LoadedRuleCount);
            var target = WriteTarget(root, "noise ALPHA123 noise BETA4567 noise");
            Assert.Contains(db.ScanFile(target, 32), m => m.RuleName == "R1");
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void ValidMultiRulePack_ReportsAccurateLoadedCount()
    {
        var root = NewRoot();
        try
        {
            WriteRule(root, "r1.yar", ValidR1);
            WriteRule(root, "r2.yar", ValidR1.Replace("R1", "R2"));
            WriteRule(root, "r3.yar", ValidR1.Replace("R1", "R3"));
            var db = LightweightYaraDatabase.Load(root, RulePackLimits.Default);
            Assert.Equal(3, db.Validation.LoadedRuleCount);
            Assert.Equal(3, db.Count);
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void MalformedFile_AmongValid_IsIsolated()
    {
        var root = NewRoot();
        try
        {
            WriteRule(root, "good.yar", ValidR1);
            WriteRule(root, "bad.yar", "rule Bad {\n  strings:\n    $a = \"ABCD1234\"\n  condition:\n    all of them\n"); // unclosed brace
            var db = LightweightYaraDatabase.Load(root, RulePackLimits.Default);
            Assert.Equal(1, db.Validation.LoadedRuleCount);          // only the good rule
            Assert.True(db.Validation.SkippedFileCount + db.Validation.FailedFileCount >= 1);
            Assert.Contains(db.Rules, r => r.Name == "R1");
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void UnsupportedImport_IsSkipped_AndNeverMatches()
    {
        var root = NewRoot();
        try
        {
            WriteRule(root, "imp.yar",
                "import \"pe\"\nrule ImpRule {\n  strings:\n    $a = \"IMPORTSTR\"\n  condition:\n    all of them\n}\n");
            var db = LightweightYaraDatabase.Load(root, RulePackLimits.Default);
            Assert.Equal(0, db.Validation.LoadedRuleCount);
            Assert.True(db.Validation.SkippedFileCount >= 1);
            Assert.Contains(db.Validation.Issues, i => i.Category == "Skipped" && i.Reason.Contains("import", StringComparison.OrdinalIgnoreCase));
            // The import rule's string must NOT produce a match (rule was not loaded).
            var target = WriteTarget(root, "xx IMPORTSTR xx");
            Assert.Empty(db.ScanFile(target, 32));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void OversizedFile_IsLimited_NotLoaded()
    {
        var root = NewRoot();
        try
        {
            WriteRule(root, "big.yar", ValidR1);
            var limits = new RulePackLimits(MaxRuleFiles: 5000, MaxRuleFileSizeBytes: 16, MaxRulePackSizeBytes: 1L << 30);
            var db = LightweightYaraDatabase.Load(root, limits);
            Assert.Equal(0, db.Validation.LoadedRuleCount);
            Assert.True(db.Validation.LimitedFileCount >= 1);
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void MaxRuleFiles_Enforced()
    {
        var root = NewRoot();
        try
        {
            WriteRule(root, "a.yar", ValidR1);
            WriteRule(root, "b.yar", ValidR1.Replace("R1", "R2"));
            var limits = new RulePackLimits(MaxRuleFiles: 1, MaxRuleFileSizeBytes: 1L << 20, MaxRulePackSizeBytes: 1L << 30);
            var db = LightweightYaraDatabase.Load(root, limits);
            Assert.Equal(1, db.Validation.LoadedRuleCount); // only the first (sorted) file
            Assert.Equal(1, db.Validation.LimitedFileCount);
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void MaxTotalPackSize_Enforced()
    {
        var root = NewRoot();
        try
        {
            WriteRule(root, "a.yar", ValidR1);
            WriteRule(root, "b.yar", ValidR1.Replace("R1", "R2"));
            long oneFile = new FileInfo(Path.Combine(root, "yara_rules", "a.yar")).Length;
            // Total budget fits exactly one file, so the second is limited.
            var limits = new RulePackLimits(MaxRuleFiles: 5000, MaxRuleFileSizeBytes: 1L << 20, MaxRulePackSizeBytes: oneFile);
            var db = LightweightYaraDatabase.Load(root, limits);
            Assert.Equal(1, db.Validation.LoadedRuleCount);
            Assert.True(db.Validation.LimitedFileCount >= 1);
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void ConfirmedRule_StillConfirms_Unchanged()
    {
        var root = NewRoot();
        try
        {
            WriteRule(root, "conf.yar",
                "rule ConfRule {\n  meta:\n    confirmed = true\n  strings:\n    $a = \"CONFIRMSTR\"\n  condition:\n    all of them\n}\n");
            var db = LightweightYaraDatabase.Load(root, RulePackLimits.Default);
            Assert.Contains(db.Rules, r => r.Name == "ConfRule" && r.Confirmed);
            var target = WriteTarget(root, "yy CONFIRMSTR yy");
            Assert.Contains(db.ScanFile(target, 32), m => m.RuleName == "ConfRule" && m.Confirmed);
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void NoArgLoad_UsesDefaultLimits_AndLoadsValid()
    {
        var root = NewRoot();
        try
        {
            WriteRule(root, "r1.yar", ValidR1);
            var db = LightweightYaraDatabase.Load(root); // default limits
            Assert.True(db.Count >= 1);
            Assert.Equal(1, db.Validation.LoadedRuleCount);
        }
        finally { Cleanup(root); }
    }
}
