using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using DataVanger.Core;
using DataVanger.Reporting;
using Xunit;

// Phase 07 — CSV export hardening. CsvSafe neutralizes spreadsheet formula
// injection and applies RFC 4180 quoting; every CSV exporter routes through it.
public class CsvSafeTests
{
    [Theory]
    [InlineData("=cmd|' /c calc'!A1")]
    [InlineData("+1+1")]
    [InlineData("-2+3")]
    [InlineData("@SUM(A1:A9)")]
    [InlineData("\tTabLed")]
    [InlineData("\rCarriageReturnLed")]
    public void NeutralizeFormula_PrefixesApostrophe_ForFormulaLeaders(string input)
    {
        Assert.StartsWith("'", CsvSafe.NeutralizeFormula(input));
    }

    [Theory]
    [InlineData("evil.exe")]
    [InlineData("C:\\Users\\me\\file.txt")]
    [InlineData("normal text")]
    public void NeutralizeFormula_LeavesNormalText_Unchanged(string input)
    {
        Assert.Equal(input, CsvSafe.NeutralizeFormula(input));
    }

    [Fact]
    public void Field_FormulaLeader_IsNeutralized()
    {
        // The dangerous leading '=' is rendered literal: the field starts with '.
        Assert.StartsWith("'=", CsvSafe.Field("=HYPERLINK(\"http://evil\")").TrimStart('"'));
    }

    [Fact]
    public void Field_QuotesCommaAndDoublesInnerQuotes()
    {
        Assert.Equal("\"a,b\"", CsvSafe.Field("a,b"));
        Assert.Equal("\"he said \"\"hi\"\"\"", CsvSafe.Field("he said \"hi\""));
    }

    [Theory]
    [InlineData("line1\nline2")]
    [InlineData("line1\r\nline2")]
    public void Field_QuotesNewlines(string input)
    {
        var result = CsvSafe.Field(input);
        Assert.StartsWith("\"", result);
        Assert.EndsWith("\"", result);
    }

    [Fact]
    public void Field_PlainValue_IsReturnedUnquoted()
    {
        Assert.Equal("evil.exe", CsvSafe.Field("evil.exe"));
    }

    [Fact]
    public void Field_FormulaWithComma_IsBothNeutralizedAndQuoted()
    {
        // '=A1,B1' -> neutralize -> '=A1,B1 ; contains comma -> quoted
        Assert.Equal("\"'=A1,B1\"", CsvSafe.Field("=A1,B1"));
    }

    [Theory] // tab/CR BEFORE a formula are themselves formula leaders -> apostrophe-prefixed
    [InlineData("\t=SUM(A1:A9)")]
    [InlineData("\r=SUM(A1:A9)")]
    public void Field_TabOrCr_BeforeFormula_IsNeutralized(string input)
    {
        Assert.StartsWith("'", CsvSafe.NeutralizeFormula(input)); // rendered as literal text
        Assert.Contains("'", CsvSafe.Field(input));               // survives the RFC 4180 quoting
    }

    [Fact] // LF-first is NOT a spreadsheet formula leader (a cell not starting at char 0 with a
           // trigger is never evaluated); it is RFC 4180-quoted so it cannot break CSV structure.
    public void Field_LfBeforeFormula_IsQuoted_NotAFormulaLeader()
    {
        Assert.Equal("\n=SUM(A1:A9)", CsvSafe.NeutralizeFormula("\n=SUM(A1:A9)")); // no apostrophe
        var result = CsvSafe.Field("\n=SUM(A1:A9)");
        Assert.StartsWith("\"", result);
        Assert.EndsWith("\"", result);
    }

    [Fact]
    public void Field_NullOrEmpty_ReturnsEmpty()
    {
        Assert.Equal("", CsvSafe.Field(null));
        Assert.Equal("", CsvSafe.Field(""));
    }

    [Fact]
    public void Field_PreservesLeadingTrailingWhitespace_ByQuoting()
    {
        Assert.Equal("\"  padded  \"", CsvSafe.Field("  padded  "));
    }

    [Fact]
    public void ScanEngine_PreviousHashes_LoadsSha256_FromValidMultilineCsvRecord()
    {
        var root = Path.Combine(Path.GetTempPath(), "dvtest_csv_prev_" + Guid.NewGuid().ToString("N"));
        var hash = new string('A', 64);
        try
        {
            Directory.CreateDirectory(root);
            File.WriteAllText(
                Path.Combine(root, "DataVanger_Report.csv"),
                "FileName,Risk,Type,SHA256\r\n\"evil\r\nname.exe\",Alto,exe," + hash + "\r\n");

            var engine = (ScanEngine)RuntimeHelpers.GetUninitializedObject(typeof(ScanEngine));
            SetBackingField(engine, nameof(ScanEngine.MgRoot), root);

            var method = typeof(ScanEngine).GetMethod("LoadPreviousHashes", BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(method);
            var hashes = Assert.IsAssignableFrom<HashSet<string>>(method!.Invoke(engine, Array.Empty<object>()));

            Assert.Contains(hash, hashes);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void SetBackingField<T>(T target, string propertyName, object value)
    {
        var field = typeof(T).GetField($"<{propertyName}>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(field);
        field!.SetValue(target, value);
    }
}
