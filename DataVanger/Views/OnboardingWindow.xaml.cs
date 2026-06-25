using System.Windows;
using DataVanger.ViewModels;

namespace DataVanger.Views;

/// <summary>
/// First-run onboarding window (Phase 07). A thin shell over
/// <see cref="OnboardingViewModel"/>: the checkboxes bind to the view model, "Apply"
/// persists the chosen (protection-only) options, and "Skip" changes nothing. Either
/// way the caller records the first-run marker so onboarding shows once. The window is
/// non-elevated and never disables a protection.
/// </summary>
public partial class OnboardingWindow : Window
{
    private readonly OnboardingViewModel _viewModel;
    private readonly string _settingsPath;

    public OnboardingWindow(OnboardingViewModel viewModel, string settingsPath)
    {
        InitializeComponent();
        _viewModel = viewModel;
        _settingsPath = settingsPath;
        DataContext = viewModel;

        BtnApply.Click += OnApply;
        // Skip changes nothing; setting DialogResult on a ShowDialog window closes it.
        BtnSkip.Click += (_, _) => DialogResult = false;
    }

    private void OnApply(object sender, RoutedEventArgs e)
    {
        // Persist only the chosen options. The view model can only ENABLE protections,
        // never disable one — so this never weakens the conservative defaults.
        _viewModel.CompleteAndSave(_settingsPath);
        DialogResult = true;
    }
}
