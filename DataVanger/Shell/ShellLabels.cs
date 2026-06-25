using DataVanger.Localization;

namespace DataVanger.Shell;

/// <summary>
/// Fachada de strings do shell. Desde a fase 01B os valores vêm dos recursos
/// de localização (pt-BR padrão, en-US parcial com fallback); os nomes dos
/// membros são estáveis para que o XAML ({x:Static}) e o view model não
/// precisem mudar quando a tradução evoluir.
/// </summary>
public static class ShellLabels
{
    public static string NavigationHeader => LocalizationService.GetString("Shell_NavigationHeader");

    public static string Dashboard   => LocalizationService.GetString("Shell_Dashboard");
    public static string Scan        => LocalizationService.GetString("Shell_Scan");
    public static string Protection  => LocalizationService.GetString("Shell_Protection");
    public static string Threats     => LocalizationService.GetString("Shell_Threats");
    public static string Quarantine  => LocalizationService.GetString("Shell_Quarantine");
    public static string Reports     => LocalizationService.GetString("Shell_Reports");
    public static string Updates     => LocalizationService.GetString("Shell_Updates");
    public static string Settings    => LocalizationService.GetString("Shell_Settings");
    public static string Diagnostics => LocalizationService.GetString("Shell_Diagnostics");

    public static string ReportsHeader          => LocalizationService.GetString("Shell_ReportsHeader");
    public static string ReportsDescription     => LocalizationService.GetString("Shell_ReportsDescription");
    public static string UpdatesHeader          => LocalizationService.GetString("Shell_UpdatesHeader");
    public static string UpdatesDescription     => LocalizationService.GetString("Shell_UpdatesDescription");
    public static string DiagnosticsHeader      => LocalizationService.GetString("Shell_DiagnosticsHeader");
    public static string DiagnosticsDescription => LocalizationService.GetString("Shell_DiagnosticsDescription");
    public static string DeferredNote           => LocalizationService.GetString("Shell_DeferredNote");
}
