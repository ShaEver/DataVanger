using DataVanger.Detection;
using Xunit;

namespace DataVanger.Tests;

/// <summary>
/// Unit tests for <see cref="DetectionModuleSet.IsEnabled"/> — the runtime gate that
/// makes the Fast profile genuinely fast (FASE 2b) by skipping expensive detectors.
///
/// What these tests pin down:
///   1. Fast profile runs only the 4 essential modules (Hash, Persistence, Yara,
///      Authenticode) and skips Heuristic, Script, PE, Archive, Document,
///      BrowserExtension.
///   2. Deep profile runs every module.
///   3. Unknown module names default to enabled (so a future module is never
///      silently dropped, and a typo in the switch fails loud in these tests).
///   4. The factory methods produce the documented flag sets.
///
/// Anti-FP note: gating only removes evidence signals, never adds trust relief, so a
/// disabled module can lower sensitivity but can never create a false positive.
/// </summary>
public class DetectionModuleSetTests
{
    [Fact]
    public void FastOnly_EnablesOnlyEssentialModules()
    {
        var fast = DetectionModuleSet.FastOnly();

        // Essential modules kept in Fast.
        Assert.True(fast.IsEnabled("HashLookup"));
        Assert.True(fast.IsEnabled("Persistence"));
        Assert.True(fast.IsEnabled("Yara"));
        // Authenticode is not a pipeline module; it resolves via the default branch.
        Assert.True(fast.IsEnabled("Authenticode"));

        // Expensive analysis layers skipped in Fast.
        Assert.False(fast.IsEnabled("Heuristic"));
        Assert.False(fast.IsEnabled("Script"));
        Assert.False(fast.IsEnabled("PeStatic"));
        Assert.False(fast.IsEnabled("Archive"));
        Assert.False(fast.IsEnabled("Document"));
        Assert.False(fast.IsEnabled("BrowserExtension"));
    }

    [Theory]
    [InlineData("HashLookup")]
    [InlineData("Heuristic")]
    [InlineData("Script")]
    [InlineData("PeStatic")]
    [InlineData("Archive")]
    [InlineData("Document")]
    [InlineData("BrowserExtension")]
    [InlineData("Yara")]
    [InlineData("Persistence")]
    public void All_EnablesEveryModule(string moduleName)
    {
        Assert.True(DetectionModuleSet.All().IsEnabled(moduleName));
    }

    [Theory]
    [InlineData("UnknownDetector")]
    [InlineData("FutureModule")]
    [InlineData("")]
    public void IsEnabled_UnknownName_DefaultsToEnabled(string unknownName)
    {
        // Default-to-enabled keeps placeholder/future modules from being dropped.
        Assert.True(DetectionModuleSet.FastOnly().IsEnabled(unknownName));
        Assert.True(DetectionModuleSet.All().IsEnabled(unknownName));
    }

    [Fact]
    public void IsEnabled_IsCaseSensitive()
    {
        var fast = DetectionModuleSet.FastOnly();

        // Exact name → mapped flag (Heuristic is off in Fast).
        Assert.False(fast.IsEnabled("Heuristic"));
        // Wrong casing is treated as an unknown name → default true.
        Assert.True(fast.IsEnabled("heuristic"));
    }

    [Fact]
    public void FastOnly_FactoryMatchesFlags()
    {
        var fast = DetectionModuleSet.FastOnly();

        Assert.True(fast.Hash);
        Assert.True(fast.Persistence);
        Assert.True(fast.Yara);
        Assert.True(fast.Authenticode);
        Assert.False(fast.Heuristic);
        Assert.False(fast.Script);
        Assert.False(fast.PE);
        Assert.False(fast.Archive);
        Assert.False(fast.Document);
        Assert.False(fast.BrowserExtension);
    }

    [Fact]
    public void All_FactoryMatchesFlags()
    {
        var deep = DetectionModuleSet.All();

        Assert.True(deep.Hash);
        Assert.True(deep.Persistence);
        Assert.True(deep.Yara);
        Assert.True(deep.Authenticode);
        Assert.True(deep.Heuristic);
        Assert.True(deep.Script);
        Assert.True(deep.PE);
        Assert.True(deep.Archive);
        Assert.True(deep.Document);
        Assert.True(deep.BrowserExtension);
    }
}
