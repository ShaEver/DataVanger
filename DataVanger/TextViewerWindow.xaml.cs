using System.Windows;

namespace DataVanger;

public partial class TextViewerWindow : Window
{
    public TextViewerWindow(string title, string content)
    {
        InitializeComponent();
        Title          = title;
        TxtContent.Text = content;
    }
}
