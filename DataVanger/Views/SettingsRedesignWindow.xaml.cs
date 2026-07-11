using System;
using System.Windows;
using DataVanger.Core;
using DataVanger.Settings;
using DataVanger.ViewModels;
using WpfCheckBox = System.Windows.Controls.CheckBox;
using WpfTextBlock = System.Windows.Controls.TextBlock;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;
using MessageBoxResult = System.Windows.MessageBoxResult;

namespace DataVanger.Views;

/// <summary>
/// Redesigned, grouped, reveal-gated settings window (Phase 06). It is a thin shell
/// over <see cref="SettingsRedesignViewModel"/>: it generates grouped toggles from the
/// metadata catalog and forwards changes to the view model. Disabling a protection
/// setting prompts a confirmation whose SAFE answer (No) is the default; re-enabling
/// never prompts. It changes no defaults/thresholds and saves through the unchanged
/// AppSettings loader.
/// </summary>
public partial class SettingsRedesignWindow : Window
{
    private readonly string _settingsPath;
    private readonly SettingsRedesignViewModel _viewModel;
    private bool _suppressEvents;

    public SettingsRedesignWindow(string settingsPath)
    {
        InitializeComponent();
        _settingsPath = settingsPath;
        _viewModel = new SettingsRedesignViewModel(AppSettings.Load(settingsPath));

        CmbReveal.SelectionChanged += (_, _) =>
        {
            _viewModel.RevealLevel = (SettingVisibility)Math.Clamp(CmbReveal.SelectedIndex, 0, 2);
            Rebuild();
        };
        BtnSave.Click += OnSave;
        BtnCancel.Click += (_, _) => Close();

        Rebuild();
    }

    private void Rebuild()
    {
        PanelGroups.Children.Clear();

        foreach (var group in _viewModel.VisibleGroups)
        {
            PanelGroups.Children.Add(new WpfTextBlock
            {
                Text = GroupLabel(group.Key),
                FontWeight = FontWeights.SemiBold,
                Foreground = System.Windows.Media.Brushes.SkyBlue,
                Margin = new Thickness(0, 12, 0, 4),
            });

            foreach (var toggle in group)
            {
                var checkBox = new WpfCheckBox
                {
                    Content = toggle.Meta.DisplayName,
                    IsChecked = _viewModel.GetValue(toggle),
                    Margin = new Thickness(6, 4, 0, 0),
                    Tag = toggle,
                    Foreground = System.Windows.Media.Brushes.White,
                };
                checkBox.Checked += OnToggleChanged;
                checkBox.Unchecked += OnToggleChanged;
                PanelGroups.Children.Add(checkBox);

                PanelGroups.Children.Add(new WpfTextBlock
                {
                    Text = toggle.Meta.Description,
                    Foreground = System.Windows.Media.Brushes.Gray,
                    FontSize = 11,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(24, 0, 0, 4),
                });
            }
        }
    }

    private void OnToggleChanged(object sender, RoutedEventArgs e)
    {
        if (_suppressEvents) return;

        var checkBox = (WpfCheckBox)sender;
        var toggle = (ToggleSetting)checkBox.Tag;
        bool newValue = checkBox.IsChecked == true;

        if (!newValue && _viewModel.RequiresDisableConfirmation(toggle, newValue: false))
        {
            var result = MessageBox.Show(
                $"Desativar \"{toggle.Meta.DisplayName}\" reduz a proteção do sistema.\n\n" +
                $"{toggle.Meta.Description}\n\nDeseja realmente desativar?",
                "DataVanger — Desativar proteção",
                MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);

            if (result != MessageBoxResult.Yes)
            {
                // User declined (or accepted the safe default): keep protection on.
                _suppressEvents = true;
                checkBox.IsChecked = true;
                _suppressEvents = false;
                return;
            }
        }

        _viewModel.SetValue(toggle, newValue);
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        _viewModel.Save(_settingsPath);
        DialogResult = true;
    }

    private static string GroupLabel(SettingGroup group) => group switch
    {
        SettingGroup.General => "Geral",
        SettingGroup.Scanning => "Varredura",
        SettingGroup.RealTimeProtection => "Proteção em tempo real",
        SettingGroup.ThreatRemoval => "Remoção de ameaças",
        SettingGroup.Quarantine => "Quarentena",
        SettingGroup.Updates => "Atualizações",
        SettingGroup.Privacy => "Privacidade",
        SettingGroup.AdvancedDiagnostics => "Diagnóstico avançado",
        SettingGroup.DeveloperExperimental => "Desenvolvedor / Experimental",
        _ => group.ToString(),
    };
}
