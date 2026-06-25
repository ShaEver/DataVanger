using DataVanger.Shared.Ipc;

namespace DataVanger.ViewModels;

/// <summary>
/// WPF-free, honest status + guidance surface for resident-service registration
/// (Phase 07). It NEVER installs a service and NEVER elevates: it only reports the
/// current connection status and explains that registering the service requires
/// administrator privileges, performed through a separate elevated step. Opening
/// this surface never requires admin. Depends only on the connection status enum
/// and a "current process elevated" flag, so it is unit-tested cross-platform.
/// </summary>
public sealed class ServiceRegistrationViewModel
{
    public ServiceRegistrationViewModel(ServiceConnectionStatus status, bool isCurrentProcessElevated)
    {
        Status = status;
        IsCurrentProcessElevated = isCurrentProcessElevated;
    }

    public ServiceConnectionStatus Status { get; }
    public bool IsCurrentProcessElevated { get; }

    public bool ServiceReachable => Status is ServiceConnectionStatus.Connected
        or ServiceConnectionStatus.DevelopmentHost or ServiceConnectionStatus.TestHost;

    public bool ServiceInstalled =>
        Status is not (ServiceConnectionStatus.NotInstalled or ServiceConnectionStatus.Unknown);

    public string StatusSummary => Status switch
    {
        ServiceConnectionStatus.Connected => "Serviço residente conectado e em execução.",
        ServiceConnectionStatus.DevelopmentHost => "Host de desenvolvimento em processo (não é um serviço real).",
        ServiceConnectionStatus.TestHost => "Host de teste em processo (não é um serviço real).",
        ServiceConnectionStatus.NotInstalled => "Serviço residente não instalado.",
        ServiceConnectionStatus.NotRunning => "Serviço residente instalado, mas não está em execução.",
        ServiceConnectionStatus.Unreachable => "Serviço residente inacessível.",
        ServiceConnectionStatus.Degraded => "Serviço residente acessível, porém degradado.",
        _ => "Estado do serviço desconhecido.",
    };

    /// <summary>Registering/installing the resident service requires admin. True when
    /// the current process is NOT elevated.</summary>
    public bool RegistrationRequiresElevation => !IsCurrentProcessElevated;

    /// <summary>Plain-language instructions. The UI never auto-elevates — it explains.</summary>
    public string ElevationInstructions => RegistrationRequiresElevation
        ? "O registro/instalação do serviço residente exige privilégios de administrador. " +
          "Execute o instalador/serviço a partir de um prompt elevado (Executar como administrador). " +
          "Esta interface NÃO solicita elevação automaticamente e continua funcionando sem privilégios de administrador."
        : "O processo atual já está elevado. O registro do serviço pode ser concluído pelo fluxo de instalação dedicado; " +
          "esta interface não executa a instalação por conta própria.";

    /// <summary>Invariant: opening/using this UI never requires administrator rights.</summary>
    public bool UiRequiresAdmin => false;
}
