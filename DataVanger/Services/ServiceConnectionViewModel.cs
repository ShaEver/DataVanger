using DataVanger.Shared.Ipc;

namespace DataVanger.Services;

/// <summary>
/// Phase 11 (Service IPC and UI Integration): a minimal, plain-C# view model
/// that exposes the resident service connection state to the main window. It
/// wraps the WPF-independent <see cref="UiServiceConnectionModel"/> from the
/// Shared project, so all of its display/gating logic is unit-tested without a
/// UI host.
///
/// Honest behavior:
///   - In this phase the desktop process does not bind an IPC transport to a
///     running service, so the default state is "Not running". The UI reports
///     that honestly and NEVER shows service-owned runtime protection as active
///     when the service is unavailable.
///   - This view model does NOT gate the existing in-process manual scanner,
///     cleaner, scheduler, or quarantine tools — those remain fully available
///     exactly as before.
/// </summary>
public sealed class ServiceConnectionViewModel
{
    private UiServiceConnectionModel _model;

    public ServiceConnectionViewModel(ServiceConnectionStatus initialStatus = ServiceConnectionStatus.NotRunning)
    {
        _model = new UiServiceConnectionModel(initialStatus);
    }

    /// <summary>Current connection status.</summary>
    public ServiceConnectionStatus Status => _model.Status;

    /// <summary>Short, honest label for the status indicator (e.g. "Service: Not running").</summary>
    public string StatusText => _model.StatusText;

    /// <summary>Longer detail suitable for a tooltip.</summary>
    public string StatusDetail => _model.StatusDetail;

    /// <summary>True only when connected to a real / development / test host.</summary>
    public bool IsConnected => _model.IsConnected;

    /// <summary>Whether service-owned runtime-only controls should be enabled.</summary>
    public bool AreServiceRuntimeControlsEnabled => _model.AreServiceRuntimeControlsEnabled;

    /// <summary>Whether the UI may present service-owned protection as active.</summary>
    public bool ShowServiceProtectionAsActive => _model.ShowServiceProtectionAsActive;

    /// <summary>
    /// Updates the connection state from a fresh observation. Pull-only: the UI
    /// calls this on view load and after explicit commands. There is no
    /// background reconnect loop here.
    /// </summary>
    public void Refresh(ServiceConnectionStatus status, bool serviceReportsActiveProtection = false)
    {
        _model = new UiServiceConnectionModel(status, serviceReportsActiveProtection);
    }
}
