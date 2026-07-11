using System.ComponentModel;

namespace DataVanger.Shell;

/// <summary>
/// One entry in the Beta navigation rail. Pure state holder (no WPF types)
/// so it can be unit-tested without a UI host.
/// </summary>
public sealed class ShellNavigationItem : INotifyPropertyChanged
{
    private bool _isSelected;

    public ShellNavigationItem(ShellSection section, string label, ShellSectionKind kind)
    {
        Section = section;
        Label = label;
        Kind = kind;
    }

    public ShellSection Section { get; }
    public string Label { get; }
    public ShellSectionKind Kind { get; }

    public bool IsSelected
    {
        get => _isSelected;
        internal set
        {
            if (_isSelected == value) return;
            _isSelected = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}
