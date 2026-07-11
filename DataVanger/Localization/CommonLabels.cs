namespace DataVanger.Localization;

/// <summary>
/// Conjunto legado representativo migrado para recursos na fase 01B —
/// apenas para provar o padrão de fallback em strings pré-existentes.
/// A migração completa das strings legadas NÃO faz parte desta fase.
/// </summary>
public static class CommonLabels
{
    public static string FooterTagline    => LocalizationService.GetString("Legacy_FooterTagline");
    public static string StartScanSection => LocalizationService.GetString("Legacy_StartScanSection");
    public static string ActionsSection   => LocalizationService.GetString("Legacy_ActionsSection");
}
