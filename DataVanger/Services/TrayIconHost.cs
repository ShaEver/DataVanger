using System;
using DataVanger.ViewModels;
using WinForms = System.Windows.Forms;

namespace DataVanger.Services;

/// <summary>
/// Persistent tray (NotifyIcon) status surface (Phase 07). It renders the
/// <see cref="TrayStatus"/> the host derives from real app state as a single tray icon
/// with an honest tooltip and a minimal context menu that only OPENS the UI, shows
/// service status, or exits. It NEVER executes remediation, never elevates, and never
/// fakes protection state. Created once (no duplicate icons) and disposed on window
/// close. Creation is fail-safe: if a NotifyIcon cannot be created (e.g. a headless
/// session) the app still runs without a tray icon.
/// </summary>
public sealed class TrayIconHost : IDisposable
{
    private readonly WinForms.NotifyIcon _icon;
    private bool _disposed;

    private TrayIconHost(WinForms.NotifyIcon icon) => _icon = icon;

    /// <summary>
    /// Create the tray host, or return null if a NotifyIcon cannot be created so the
    /// caller degrades gracefully. The callbacks only open the UI, show the service
    /// status surface, or exit — never remediation.
    /// </summary>
    public static TrayIconHost? TryCreate(Action onOpen, Action onServiceStatus, Action onExit)
    {
        try
        {
            var menu = new WinForms.ContextMenuStrip();
            menu.Items.Add("Abrir DataVanger", null, (_, _) => onOpen());
            menu.Items.Add("Estado do serviço…", null, (_, _) => onServiceStatus());
            menu.Items.Add(new WinForms.ToolStripSeparator());
            menu.Items.Add("Sair", null, (_, _) => onExit());

            var icon = new WinForms.NotifyIcon
            {
                Icon = LoadAppIcon(),
                Visible = true,
                Text = "DataVanger",
                ContextMenuStrip = menu,
            };
            icon.DoubleClick += (_, _) => onOpen();
            return new TrayIconHost(icon);
        }
        catch (Exception)
        {
            // No tray surface available; the app runs normally without it.
            return null;
        }
    }

    /// <summary>Update the tooltip to the honest status (NotifyIcon.Text is short).</summary>
    public void Update(TrayStatus status)
    {
        if (_disposed) return;
        try
        {
            string text = "DataVanger — " + TrayStatusModel.Describe(status);
            _icon.Text = text.Length > 63 ? text.Substring(0, 63) : text;
        }
        catch (Exception)
        {
            // Tooltip update is cosmetic; never throw to the UI.
        }
    }

    /// <summary>Show a tray balloon for an urgent (action-needed / degraded) status only.</summary>
    public void Notify(TrayStatus status, string message)
    {
        if (_disposed || !TrayStatusModel.ShouldToast(status)) return;
        try
        {
            _icon.BalloonTipTitle = "DataVanger — " + TrayStatusModel.Describe(status);
            _icon.BalloonTipText = message;
            _icon.ShowBalloonTip(5000);
        }
        catch (Exception)
        {
            // Best-effort notification; never throw to the UI.
        }
    }

    private static System.Drawing.Icon LoadAppIcon()
    {
        try
        {
            var info = System.Windows.Application.GetResourceStream(new Uri("pack://application:,,,/app.ico"));
            if (info?.Stream is not null)
            {
                using var stream = info.Stream;
                return new System.Drawing.Icon(stream);
            }
        }
        catch (Exception)
        {
            // Fall through to a system icon.
        }
        return System.Drawing.SystemIcons.Application;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            _icon.Visible = false;
            _icon.ContextMenuStrip?.Dispose();
            _icon.Dispose();
        }
        catch (Exception)
        {
            // Disposal is best-effort.
        }
    }
}
