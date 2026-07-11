namespace DataVanger.Localization;

/// <summary>
/// Resource-backed facade for Removal Center UI chrome (Phase 05). Member names
/// are stable so XAML <c>{x:Static}</c> bindings do not change when translations
/// evolve. pt-BR is the neutral default; en-US is a partial scaffold with
/// fallback (matching the 01B i18n pattern).
/// </summary>
public static class RemovalCenterLabels
{
    public static string WindowTitle      => LocalizationService.GetString("RemovalCenter_WindowTitle");
    public static string Header           => LocalizationService.GetString("RemovalCenter_Header");
    public static string RecommendedAction => LocalizationService.GetString("RemovalCenter_RecommendedAction");
    public static string Target           => LocalizationService.GetString("RemovalCenter_Target");
    public static string Risk             => LocalizationService.GetString("RemovalCenter_Risk");
    public static string PlanHeader       => LocalizationService.GetString("RemovalCenter_PlanHeader");
    public static string Proceed          => LocalizationService.GetString("RemovalCenter_Proceed");
    public static string ConfirmRemove    => LocalizationService.GetString("RemovalCenter_ConfirmRemove");
    public static string Cancel           => LocalizationService.GetString("RemovalCenter_Cancel");
    public static string Close            => LocalizationService.GetString("RemovalCenter_Close");
    public static string ConfirmTitle     => LocalizationService.GetString("RemovalCenter_ConfirmTitle");
    public static string ConfirmMessage   => LocalizationService.GetString("RemovalCenter_ConfirmMessage");
    public static string EntryButton      => LocalizationService.GetString("RemovalCenter_EntryButton");
}
