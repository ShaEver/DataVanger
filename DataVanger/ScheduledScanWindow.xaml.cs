using System;
using System.Windows;
using System.Windows.Controls;
using DataVanger.Core;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;

namespace DataVanger;

public partial class ScheduledScanWindow : Window
{
    public bool RemoveRequested { get; private set; }
    public bool Weekly { get; private set; }
    public string ScheduleMode { get; private set; } = "ONCE";
    public DateTime ScheduledAt { get; private set; }
    public string WeekDay { get; private set; } = "SUN";
    public ScanProfile Profile { get; private set; } = ScanProfile.Deep;

    public ScheduledScanWindow()
    {
        InitializeComponent();
        DpDate.SelectedDate = DateTime.Today.AddDays(1);
        TxtTime.Text = "08:00";

        BtnCancel.Click += (_, _) => { DialogResult = false; };
        BtnRemove.Click += (_, _) =>
        {
            RemoveRequested = true;
            DialogResult = true;
        };
        BtnSave.Click += OnSave;
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        if (DpDate.SelectedDate == null)
        {
            MessageBox.Show("Escolha uma data.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!TimeSpan.TryParse(TxtTime.Text.Trim(), out var time))
        {
            MessageBox.Show("Hora inválida. Use o formato HH:mm, por exemplo 21:30.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        ScheduleMode = (CmbMode.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "ONCE";
        Weekly = ScheduleMode == "WEEKLY";
        ScheduledAt = DpDate.SelectedDate.Value.Date.Add(time);
        WeekDay = (CmbWeekDay.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "SUN";

        string profileText = (CmbProfile.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Deep";
        Profile = profileText.Equals("Fast", StringComparison.OrdinalIgnoreCase) ? ScanProfile.Fast : ScanProfile.Deep;

        if (ScheduleMode == "ONCE" && ScheduledAt <= DateTime.Now)
        {
            MessageBox.Show("Escolha uma data e hora no futuro.", "DataVanger", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        DialogResult = true;
    }
}
