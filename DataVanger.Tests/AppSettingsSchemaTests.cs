using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;
using DataVanger.Core;

// Phase 10 — AppSettings schema versioning + deterministic, lossless migration.
// Verifies version stamping, null/absent/empty/custom list handling, unknown-field
// tolerance, malformed-JSON resilience, and that no curated publisher default changed.
// Pure/observable behaviour via temp files; no production visibility changes.
public class AppSettingsSchemaTests
{
    private static string TempPath() =>
        Path.Combine(Path.GetTempPath(), "dvtest_schema_" + Guid.NewGuid().ToString("N") + ".json");

    private static AppSettings LoadJson(string json, out string path)
    {
        path = TempPath();
        File.WriteAllText(path, json);
        return AppSettings.Load(path);
    }

    private static void Cleanup(string path)
    {
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort cleanup */ }
    }

    private static bool ContainsCi(IEnumerable<string> list, string needle) =>
        list.Any(p => p.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0);

    [Fact]
    public void NewInstance_DefaultsToCurrentSchemaVersion()
    {
        Assert.Equal(AppSettings.CurrentSchemaVersion, new AppSettings().SchemaVersion);
    }

    [Fact]
    public void Default_TrustedPublishers_ExcludeOpenAiWondershareSweetLabs()
    {
        var s = new AppSettings();
        Assert.False(ContainsCi(s.TrustedPublishers, "OpenAI"), "OpenAI must not be a default trusted publisher.");
        Assert.False(ContainsCi(s.TrustedPublishers, "Wondershare"), "Wondershare must not be a default trusted publisher.");
        Assert.False(ContainsCi(s.TrustedPublishers, "SweetLabs"), "SweetLabs must not be a default trusted publisher.");
        Assert.True(ContainsCi(s.TrustedPublishers, "Microsoft"));
    }

    [Fact]
    public void Load_OldSettingsWithoutSchemaVersion_MigratesToCurrentVersion()
    {
        var s = LoadJson("{ \"MinScoreToReport\": 6 }", out var path);
        try { Assert.Equal(AppSettings.CurrentSchemaVersion, s.SchemaVersion); }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Load_OldSettingsWithoutTrustedPublishers_UsesCuratedDefaults()
    {
        var s = LoadJson("{ \"MinScoreToReport\": 6 }", out var path);
        try
        {
            Assert.True(ContainsCi(s.TrustedPublishers, "Microsoft"));
            Assert.False(ContainsCi(s.TrustedPublishers, "OpenAI"));
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Load_ExplicitEmptyTrustedPublishers_PreservesEmptyList()
    {
        var s = LoadJson("{ \"TrustedPublishers\": [] }", out var path);
        try
        {
            Assert.NotNull(s.TrustedPublishers);
            Assert.Empty(s.TrustedPublishers); // user intentionally cleared it — must not re-inject defaults
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Load_NullTrustedPublishers_UsesSafeDefaults()
    {
        var s = LoadJson("{ \"TrustedPublishers\": null }", out var path);
        try
        {
            Assert.NotNull(s.TrustedPublishers); // null normalised to safe non-null
            Assert.True(ContainsCi(s.TrustedPublishers, "Microsoft"));
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Load_NullExtraTrustedPublishers_UsesEmptyList()
    {
        var s = LoadJson("{ \"ExtraTrustedPublishers\": null }", out var path);
        try
        {
            Assert.NotNull(s.ExtraTrustedPublishers);
            Assert.Empty(s.ExtraTrustedPublishers);
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Load_CustomTrustedPublishers_PreservesUserValues()
    {
        var s = LoadJson("{ \"TrustedPublishers\": [\"Contoso Signing\"] }", out var path);
        try
        {
            Assert.Single(s.TrustedPublishers);
            Assert.Contains("Contoso Signing", s.TrustedPublishers);
            Assert.False(ContainsCi(s.TrustedPublishers, "Microsoft")); // user list replaces defaults, not merged
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Load_CustomExtraTrustedPublishers_PreservesUserValues()
    {
        var s = LoadJson("{ \"ExtraTrustedPublishers\": [\"Acme Ltda\"] }", out var path);
        try { Assert.Contains("Acme Ltda", s.ExtraTrustedPublishers); }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Save_CurrentSettings_PersistsSchemaVersion()
    {
        var path = TempPath();
        try
        {
            new AppSettings().Save(path);
            var raw = File.ReadAllText(path);
            Assert.Contains("\"SchemaVersion\"", raw);
            var reloaded = AppSettings.Load(path);
            Assert.Equal(AppSettings.CurrentSchemaVersion, reloaded.SchemaVersion);
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Load_UnknownFutureField_IgnoresField()
    {
        var s = LoadJson("{ \"SomeFutureField\": 123, \"MinScoreToReport\": 7 }", out var path);
        try
        {
            Assert.Equal(7, s.MinScoreToReport);                       // known field still applied
            Assert.Equal(AppSettings.CurrentSchemaVersion, s.SchemaVersion); // no throw on unknown field
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Load_MalformedJson_ReturnsSafeDefaults()
    {
        var s = LoadJson("{ this is not valid json ", out var path);
        try
        {
            Assert.Equal(AppSettings.CurrentSchemaVersion, s.SchemaVersion);
            Assert.True(ContainsCi(s.TrustedPublishers, "Microsoft")); // safe defaults, never throws to caller
        }
        finally { Cleanup(path); }
    }
}
