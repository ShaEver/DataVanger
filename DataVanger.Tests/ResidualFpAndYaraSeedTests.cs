using System;
using System.IO;
using DataVanger.Core;
using DataVanger.Detection;
using DataVanger.Engine;
using Xunit;

// Definitive-fix regression: residual false-positive drivers + YARA starter pack.
//
// 1. System-process names have a canonical home; the masquerading heuristic must
//    NOT fire there. explorer.exe legitimately lives in the Windows root (and
//    SysWOW64), not System32 — the real shell was being false-flagged.
// 2. DataVanger's own signature data is never a scan target (so rule files can't
//    self-match the lightweight substring engine).
// 3. The bundled YARA starter pack makes the engine load at least one rule
//    (YaraRulesLoaded > 0), and the loader accepts both .yar and .yara.
//
// These are OS-independent (the canonical-home check uses the windir-relative
// internal overload), so they run on the Linux CI. Real-machine FP measurement is
// covered by the manual DeepScan validation plan.
// Filters: ~ResidualFp, ~Yara, ~Detection, ~Scan.
public class ResidualFpAndYaraSeedTests
{
    private const string Win = @"c:\windows\";

    // ── A1: system-exe canonical home (the explorer.exe fix) ─────────────────

    [Theory]
    [InlineData(@"c:\windows\explorer.exe", "explorer.exe")]          // real shell home
    [InlineData(@"c:\windows\syswow64\explorer.exe", "explorer.exe")] // 32-bit shell home
    [InlineData(@"c:\windows\system32\svchost.exe", "svchost.exe")]   // service host home
    [InlineData(@"c:\windows\syswow64\rundll32.exe", "rundll32.exe")]
    public void SystemExe_InCanonicalHome_IsRecognized(string full, string name)
        => Assert.True(PathTaxonomy.IsSystemExeInCanonicalHome(full, name, Win));

    [Theory]
    [InlineData(@"c:\users\sonic\appdata\local\temp\explorer.exe", "explorer.exe")] // dropped copy
    [InlineData(@"c:\windows\svchost.exe", "svchost.exe")]   // svchost does NOT live in the windir root
    [InlineData(@"c:\temp\system32\explorer.exe", "explorer.exe")] // look-alike path
    [InlineData(@"c:\program files\app\explorer.exe", "explorer.exe")]
    public void SystemExe_OutsideCanonicalHome_IsNotRecognized(string full, string name)
        => Assert.False(PathTaxonomy.IsSystemExeInCanonicalHome(full, name, Win));

    // ── A3: DataVanger signature data is excluded from scanning ──────────────

    [Theory]
    [InlineData(@"c:\program files\datavanger\signatures.default\yara_rules\eicar.yar")]
    [InlineData(@"c:\program files\datavanger\signatures.default\known_malicious_sha256.txt")]
    public void ProductSignatureData_IsExcludedFromScan(string path)
        => Assert.True(TargetDiscovery.IsExcludedPath(path.ToLowerInvariant(), new AppSettings()));

    [Fact]
    public void OrdinaryUserFile_IsNotExcludedByDefault()
        => Assert.False(TargetDiscovery.IsExcludedPath(
            @"c:\users\sonic\documents\report.docx", new AppSettings()));

    // ── A3: the YARA starter pack loads (RuleCount > 0), .yar and .yara both ─

    [Fact]
    public void LightweightYara_LoadsBothYarAndYaraRules_RuleCountAboveZero()
    {
        string root = Path.Combine(Path.GetTempPath(), "dv_yara_" + Guid.NewGuid().ToString("N"));
        string rules = Path.Combine(root, "yara_rules");
        Directory.CreateDirectory(rules);
        try
        {
            File.WriteAllText(Path.Combine(rules, "eicar.yar"),
                "rule EICAR_Test_File { strings: $a = \"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\" condition: $a }");
            File.WriteAllText(Path.Combine(rules, "extra.yara"),
                "rule Sample_Marker { strings: $a = \"DATAVANGER-YARA-STARTER-MARKER-XYZ\" condition: $a }");

            var db = LightweightYaraDatabase.Load(root);

            Assert.True(db.Count >= 2,
                $"Starter pack must load .yar AND .yara rules; loaded {db.Count}.");
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch (Exception) { /* best-effort cleanup */ }
        }
    }
}
