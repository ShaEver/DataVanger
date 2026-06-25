using System.Linq;
using System.Text;
using System.Windows;
using DataVanger.Shared.Status;

namespace DataVanger;

/// <summary>
/// Phase 18 — read-only honest module-state panel. It only renders the
/// <see cref="CodeRealityModuleMatrix"/> as text; it writes no settings, activates no
/// modules, starts no services, and triggers no scans/updates.
/// </summary>
public partial class ModuleStatusWindow : Window
{
    public ModuleStatusWindow()
    {
        InitializeComponent();
        TxtStatus.Text = BuildReport();
    }

    private static string BuildReport()
    {
        var modules = CodeRealityModuleMatrix.Create();
        var sb = new StringBuilder();
        // Group by honest state so operators see Active vs Prepared/Fallback/Stub/... at a glance.
        foreach (var group in modules.GroupBy(m => m.State).OrderBy(g => g.Key.ToString()))
        {
            sb.Append("== ").Append(group.Key).AppendLine(" ==");
            foreach (var m in group)
            {
                sb.Append("  - ").Append(m.DisplayName).AppendLine();
                if (!string.IsNullOrWhiteSpace(m.Detail))
                    sb.Append("      ").AppendLine(m.Detail);
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }
}
