using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Resources;
using System.Threading;

namespace DataVanger.Localization;

/// <summary>
/// Beta 01B — infraestrutura mínima de localização.
///
/// Regras desta fase:
///   - pt-BR é o idioma padrão do produto (recursos neutros = pt-BR;
///     NeutralLanguage=pt-BR no csproj). O padrão é determinístico e NÃO
///     depende da cultura do sistema operacional — sem opt-in explícito o
///     aplicativo continua exatamente em português, como no Alpha.
///   - en-US existe como scaffold parcial; chaves ausentes caem de forma
///     determinística para o recurso neutro (pt-BR) via cadeia de fallback
///     do ResourceManager.
///   - Chave inexistente nunca produz texto em branco: retorna um marcador
///     visível ("![chave]!") e registra a chave para diagnóstico de
///     desenvolvimento.
///   - Nunca localizar identificadores, comandos IPC, campos serializados de
///     DTO ou chaves de configuração persistidas.
///   - Seleção de cultura não requer elevação (variável de ambiente ou
///     argumento de linha de comando, ambos por usuário).
/// </summary>
public static class LocalizationService
{
    public const string DefaultCultureName = "pt-BR";
    public const string CultureArgName = "--ui-culture";
    public const string CultureEnvVarName = "DATAVANGER_UI_CULTURE";

    private static readonly ResourceManager Resources =
        new("DataVanger.Localization.UiStrings", typeof(LocalizationService).Assembly);

    private static readonly ConcurrentDictionary<string, byte> MissingKeyRegistry = new();

    /// <summary>Cultura de UI atual usada nas buscas de recursos.</summary>
    public static CultureInfo CurrentCulture { get; private set; } =
        CultureInfo.GetCultureInfo(DefaultCultureName);

    /// <summary>Chaves solicitadas e não encontradas em nenhuma cultura —
    /// visíveis para testes e diagnóstico de desenvolvimento.</summary>
    public static IReadOnlyCollection<string> MissingKeys => MissingKeyRegistry.Keys.ToArray();

    /// <summary>
    /// Aplica a cultura de inicialização: padrão pt-BR, com opt-in explícito
    /// via "--ui-culture &lt;nome&gt;" ou variável de ambiente
    /// DATAVANGER_UI_CULTURE. Nome inválido cai para o padrão.
    /// </summary>
    public static void ApplyStartupCulture(string[]? args)
        => ApplyCulture(ReadExplicitCultureRequest(args) ?? DefaultCultureName);

    /// <summary>
    /// Define a cultura de UI para buscas de recursos. Afeta apenas idioma de
    /// interface (CurrentUICulture); formatação de números/datas
    /// (CurrentCulture de thread) permanece intocada para não alterar
    /// comportamento existente.
    /// </summary>
    public static void ApplyCulture(string cultureName)
    {
        CultureInfo culture;
        try
        {
            // predefinedOnly: sob ICU (Linux e Windows modernos), GetCultureInfo
            // sem essa flag aceita nomes sintéticos quase arbitrários e nunca
            // lançaria — o fallback para pt-BR não seria determinístico.
            culture = CultureInfo.GetCultureInfo(cultureName, predefinedOnly: true);
        }
        catch (CultureNotFoundException)
        {
            culture = CultureInfo.GetCultureInfo(DefaultCultureName);
        }

        CurrentCulture = culture;
        CultureInfo.DefaultThreadCurrentUICulture = culture;
        Thread.CurrentThread.CurrentUICulture = culture;
    }

    internal static string? ReadExplicitCultureRequest(string[]? args)
    {
        if (args is not null)
        {
            for (int i = 0; i < args.Length - 1; i++)
            {
                if (string.Equals(args[i], CultureArgName, StringComparison.OrdinalIgnoreCase))
                    return args[i + 1];
            }
        }

        var env = Environment.GetEnvironmentVariable(CultureEnvVarName);
        return string.IsNullOrWhiteSpace(env) ? null : env.Trim();
    }

    /// <summary>
    /// Busca um recurso de UI. Fallback determinístico: cultura atual →
    /// cultura pai → neutro (pt-BR). Nunca retorna nulo/vazio: chave
    /// totalmente ausente devolve um marcador visível e é registrada.
    /// </summary>
    public static string GetString(string key)
    {
        string? value;
        try
        {
            value = Resources.GetString(key, CurrentCulture);
        }
        catch (MissingManifestResourceException)
        {
            value = null;
        }

        if (string.IsNullOrEmpty(value))
        {
            MissingKeyRegistry.TryAdd(key, 0);
            return "![" + key + "]!";
        }

        return value;
    }
}
