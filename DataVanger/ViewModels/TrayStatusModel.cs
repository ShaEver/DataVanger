namespace DataVanger.ViewModels;

/// <summary>Tray surface status (Phase 07), highest-priority first.</summary>
public enum TrayStatus
{
    Protected = 0,
    UpdateAvailable,
    RemediationInProgress,
    ProtectionDegraded,
    ActionNeeded,
}

/// <summary>
/// Pure derivation of the tray status from current conditions. WPF-free and
/// deterministic so it can be unit-tested and reused by any tray host. The actual
/// tray icon/notification host is a Windows-only surface that renders this status.
/// </summary>
public static class TrayStatusModel
{
    /// <summary>
    /// Resolve the single status to show. Priority (most urgent first):
    /// action-needed (a threat awaits the user) → protection degraded (real-time
    /// off / service degraded) → remediation in progress → update available →
    /// protected.
    /// </summary>
    public static TrayStatus Derive(
        bool realtimeActive,
        bool pendingThreats,
        bool serviceDegraded,
        bool updateAvailable,
        bool remediationInProgress)
    {
        if (pendingThreats) return TrayStatus.ActionNeeded;
        if (serviceDegraded || !realtimeActive) return TrayStatus.ProtectionDegraded;
        if (remediationInProgress) return TrayStatus.RemediationInProgress;
        if (updateAvailable) return TrayStatus.UpdateAvailable;
        return TrayStatus.Protected;
    }

    /// <summary>Plain-language pt-BR description for the tooltip/notification.</summary>
    public static string Describe(TrayStatus status) => status switch
    {
        TrayStatus.Protected => "Protegido",
        TrayStatus.UpdateAvailable => "Atualização disponível",
        TrayStatus.RemediationInProgress => "Remediação em andamento",
        TrayStatus.ProtectionDegraded => "Proteção reduzida",
        TrayStatus.ActionNeeded => "Ação necessária",
        _ => "Desconhecido",
    };

    /// <summary>Whether this status warrants a tray toast (vs. a silent log update).
    /// Decisions/consent are handled by modal dialogs elsewhere, not here.</summary>
    public static bool ShouldToast(TrayStatus status)
        => status is TrayStatus.ActionNeeded or TrayStatus.ProtectionDegraded;
}
