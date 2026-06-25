namespace DataVanger.Localization;

/// <summary>
/// Resource-backed facade for first-run onboarding UI chrome (Phase 07). pt-BR is
/// the neutral default; en-US is a partial scaffold with fallback. Member names are
/// stable so XAML <c>{x:Static}</c> bindings do not change when translations evolve.
/// </summary>
public static class OnboardingLabels
{
    public static string WindowTitle      => LocalizationService.GetString("Onboarding_WindowTitle");
    public static string Header           => LocalizationService.GetString("Onboarding_Header");
    public static string Intro            => LocalizationService.GetString("Onboarding_Intro");
    public static string RealtimeOption   => LocalizationService.GetString("Onboarding_RealtimeOption");
    public static string AutoQuarantine   => LocalizationService.GetString("Onboarding_AutoQuarantine");
    public static string StartWithWindows => LocalizationService.GetString("Onboarding_StartWithWindows");
    public static string Apply            => LocalizationService.GetString("Onboarding_Apply");
    public static string Skip             => LocalizationService.GetString("Onboarding_Skip");
    public static string SafetyNote       => LocalizationService.GetString("Onboarding_SafetyNote");
}
