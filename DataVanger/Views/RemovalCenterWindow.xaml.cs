using System.ComponentModel;
using System.Windows;
using DataVanger.ViewModels;

namespace DataVanger.Views;

/// <summary>
/// Host window for the Removal Center. It is a thin shell over
/// <see cref="RemovalCenterViewModel"/>: it renders bound state and forwards
/// button clicks to the view model. It performs no remediation itself and holds
/// no engine reference; the view model talks to the service over IPC.
///
/// Destructive-dialog standard: in the confirmation state the SAFE action
/// (cancel) is the default button and receives focus; the destructive confirm
/// button is never the default.
/// </summary>
public partial class RemovalCenterWindow : Window
{
    private readonly RemovalCenterViewModel _viewModel;

    public RemovalCenterWindow(RemovalCenterViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = viewModel;
        _viewModel.PropertyChanged += OnViewModelPropertyChanged;

        BtnProceed.Click += async (_, _) => await _viewModel.ProceedAsync();
        BtnConfirm.Click += async (_, _) => await _viewModel.ConfirmAsync();
        BtnCancel.Click += (_, _) => _viewModel.CancelConfirmation();
        BtnClose.Click += (_, _) => Close();

        RefreshControls();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
        => RefreshControls();

    private void RefreshControls()
    {
        bool awaiting = _viewModel.State == RemovalCenterState.AwaitingConfirmation;

        BtnProceed.Visibility = awaiting ? Visibility.Collapsed : Visibility.Visible;
        BtnProceed.IsEnabled = _viewModel.CanProceed;

        BtnConfirm.Visibility = awaiting ? Visibility.Visible : Visibility.Collapsed;
        BtnConfirm.IsEnabled = _viewModel.CanConfirm;

        BtnCancel.Visibility = awaiting ? Visibility.Visible : Visibility.Collapsed;

        // Safe default: when a destructive action awaits confirmation, focus the
        // cancel button so Enter/space resolves to the safe choice.
        if (awaiting)
            BtnCancel.Focus();
    }
}
