using System;
using System.Linq;
using System.Reflection;
using DataVanger.Localization;
using DataVanger.Shell;
using Xunit;

// Beta phase 01B — localization scaffold tests. Runnable via:
//   dotnet test --filter "FullyQualifiedName~Localization"
// Contract under test: pt-BR is the deterministic default; en-US is a partial
// scaffold whose missing keys fall back to pt-BR; a fully unknown key returns
// a visible developer marker, never blank; culture selection never requires
// elevation (env var / CLI arg only).
public class LocalizationTests : IDisposable
{
    public LocalizationTests() => LocalizationService.ApplyCulture(LocalizationService.DefaultCultureName);

    public void Dispose() => LocalizationService.ApplyCulture(LocalizationService.DefaultCultureName);

    [Fact]
    public void DefaultCulture_IsPtBr_AndResolvesPortugueseStrings()
    {
        LocalizationService.ApplyStartupCulture(args: null);

        Assert.Equal("pt-BR", LocalizationService.CurrentCulture.Name);
        Assert.Equal("Painel", LocalizationService.GetString("Shell_Dashboard"));
        Assert.Equal("Quarentena", LocalizationService.GetString("Shell_Quarantine"));
        Assert.Equal("NAVEGAÇÃO", LocalizationService.GetString("Shell_NavigationHeader"));
    }

    [Fact]
    public void ShellLabels_AreResourceBacked_InDefaultCulture()
    {
        Assert.Equal("Painel", ShellLabels.Dashboard);
        Assert.Equal("Varredura", ShellLabels.Scan);
        Assert.Equal("Configurações", ShellLabels.Settings);
        Assert.Equal("Diagnóstico Avançado", ShellLabels.Diagnostics);
    }

    [Fact]
    public void EnUs_PartialScaffold_UsesEnglishWhereAvailable()
    {
        LocalizationService.ApplyCulture("en-US");

        Assert.Equal("Dashboard", ShellLabels.Dashboard);
        Assert.Equal("Quarantine", ShellLabels.Quarantine);
        Assert.Equal("NAVIGATION", ShellLabels.NavigationHeader);
    }

    [Fact]
    public void EnUs_MissingKeys_FallBackToPortuguese_NeverBlank()
    {
        LocalizationService.ApplyCulture("en-US");

        // Deliberately untranslated in the en-US scaffold:
        Assert.Equal("A linha do tempo completa de eventos e ações chega em uma fase futura do Beta.",
            ShellLabels.DeferredNote);
        Assert.Equal("DataVanger - Scanner defensivo local", CommonLabels.FooterTagline);
        Assert.Equal("AÇÕES", CommonLabels.ActionsSection);
    }

    [Fact]
    public void UnknownKey_ReturnsVisibleMarker_AndIsRecorded_NeverBlank()
    {
        var key = "Test_DoesNotExist_" + Guid.NewGuid().ToString("N");

        var value = LocalizationService.GetString(key);

        Assert.False(string.IsNullOrWhiteSpace(value));
        Assert.Equal("![" + key + "]!", value);
        Assert.Contains(key, LocalizationService.MissingKeys);
    }

    [Fact]
    public void InvalidCultureName_FallsBackToDefault()
    {
        LocalizationService.ApplyCulture("xx-INVALID-CULTURE");

        Assert.Equal("pt-BR", LocalizationService.CurrentCulture.Name);
        Assert.Equal("Painel", ShellLabels.Dashboard);
    }

    [Fact]
    public void ExplicitCultureRequest_ComesFromArg_NotElevation()
    {
        var fromArg = LocalizationService.ReadExplicitCultureRequest(
            new[] { "--silent", LocalizationService.CultureArgName, "en-US" });
        var none = LocalizationService.ReadExplicitCultureRequest(new[] { "--silent" });

        Assert.Equal("en-US", fromArg);
        // Sem argumento, depende apenas da env var (não setada em testes) — nulo.
        if (string.IsNullOrWhiteSpace(
                Environment.GetEnvironmentVariable(LocalizationService.CultureEnvVarName)))
            Assert.Null(none);
    }

    [Fact]
    public void AllShellLabelMembers_NonBlank_NoMissingMarkers_InBothCultures()
    {
        var properties = typeof(ShellLabels)
            .GetProperties(BindingFlags.Public | BindingFlags.Static)
            .Where(p => p.PropertyType == typeof(string))
            .ToArray();
        Assert.NotEmpty(properties);

        foreach (var cultureName in new[] { "pt-BR", "en-US" })
        {
            LocalizationService.ApplyCulture(cultureName);
            foreach (var property in properties)
            {
                var value = (string?)property.GetValue(null);
                Assert.False(string.IsNullOrWhiteSpace(value),
                    $"{property.Name} em branco na cultura {cultureName}");
                Assert.False(value!.StartsWith("![", StringComparison.Ordinal),
                    $"{property.Name} sem recurso na cultura {cultureName}: {value}");
            }
        }
    }
}
