using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Remediation;

namespace DataVanger.ViewModels;

/// <summary>
/// MVVM brain of the Removal Center. It is WPF-free (no UI types; only
/// presentation state and <see cref="INotifyPropertyChanged"/>), so it is unit
/// tested without a UI host. It is a consent and visualization surface: it builds
/// a request DTO and renders the service response. It never executes remediation
/// locally, never references the engine, and never lowers a policy confirmation
/// requirement — the authoritative band, evidence, consent, and policy decision
/// all live server-side.
/// </summary>
public sealed class RemovalCenterViewModel : INotifyPropertyChanged
{
    private readonly IRemovalCenterService _service;
    private RemovalCenterThreatContext? _context;

    private RemovalCenterState _state = RemovalCenterState.Empty;
    private bool _isBusy;
    private string _statusMessage = string.Empty;
    private string _resultMessage = string.Empty;
    private bool _requiresReboot;
    private bool _requiresVerification;
    private IReadOnlyList<RemovalCenterStepView> _steps = Array.Empty<RemovalCenterStepView>();

    public RemovalCenterViewModel(IRemovalCenterService service)
        => _service = service ?? throw new ArgumentNullException(nameof(service));

    public event PropertyChangedEventHandler? PropertyChanged;

    public RemovalCenterState State
    {
        get => _state;
        private set { if (SetField(ref _state, value)) RaiseCommandState(); }
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set { if (SetField(ref _isBusy, value)) RaiseCommandState(); }
    }

    public string StatusMessage { get => _statusMessage; private set => SetField(ref _statusMessage, value); }
    public string ResultMessage { get => _resultMessage; private set => SetField(ref _resultMessage, value); }
    public bool RequiresReboot { get => _requiresReboot; private set => SetField(ref _requiresReboot, value); }
    public bool RequiresVerification { get => _requiresVerification; private set => SetField(ref _requiresVerification, value); }
    public IReadOnlyList<RemovalCenterStepView> Steps { get => _steps; private set => SetField(ref _steps, value); }

    public string Title => _context?.Title ?? string.Empty;
    public string RiskText => _context?.RiskText ?? string.Empty;
    public string TargetText => _context?.TargetIdentity ?? string.Empty;
    public string RecommendedActionText => _context is null ? string.Empty : DescribeAction(_context.Action);

    /// <summary>True for any removal / system-scope / locked-file action
    /// (everything except quarantine-containment and verification). A destructive
    /// action requires an explicit, safe-default confirmation before the request
    /// is sent — the UI must never skip it.</summary>
    public bool IsDestructive => _context is not null && IsDestructiveAction(_context.Action);

    public bool RequiresConfirmation => IsDestructive;

    /// <summary>The destructive-dialog standard: the safe action (cancel) is the
    /// default. Always true; the UI binds its default/cancel button to this.</summary>
    public bool SafeDefaultIsCancel => true;

    public bool ServiceAvailable => _service.IsAvailable;

    public bool CanProceed => State == RemovalCenterState.PlanReady && !IsBusy && ServiceAvailable;
    public bool CanConfirm => State == RemovalCenterState.AwaitingConfirmation && !IsBusy && ServiceAvailable;
    public bool CanCancelConfirmation => State == RemovalCenterState.AwaitingConfirmation && !IsBusy;

    /// <summary>Load a threat + intended action. Contacts nothing and executes
    /// nothing; only moves the surface to <see cref="RemovalCenterState.PlanReady"/>.</summary>
    public void Prepare(RemovalCenterThreatContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        ResultMessage = ServiceAvailable
            ? string.Empty
            : "Serviço de remediação indisponível. Nenhuma ação foi executada.";
        StatusMessage = string.Empty;
        RequiresReboot = false;
        RequiresVerification = false;
        Steps = Array.Empty<RemovalCenterStepView>();
        State = RemovalCenterState.PlanReady;
        RaiseContextDerived();
    }

    /// <summary>
    /// User asked to proceed. A destructive action first moves to
    /// <see cref="RemovalCenterState.AwaitingConfirmation"/> (safe default = cancel);
    /// a non-destructive action (quarantine/verify) is sent straight to the policy
    /// gate over IPC. Never executes locally.
    /// </summary>
    public Task ProceedAsync(CancellationToken cancellationToken = default)
    {
        if (State != RemovalCenterState.PlanReady) return Task.CompletedTask;
        if (!ServiceAvailable)
        {
            State = RemovalCenterState.Failed;
            ResultMessage = "Serviço de remediação indisponível. Nenhuma ação foi executada.";
            return Task.CompletedTask;
        }
        if (IsDestructive)
        {
            State = RemovalCenterState.AwaitingConfirmation;
            return Task.CompletedTask;
        }
        return ExecuteAsync(cancellationToken);
    }

    /// <summary>User cancelled the destructive confirmation. Returns to the plan,
    /// having done nothing.</summary>
    public void CancelConfirmation()
    {
        if (State == RemovalCenterState.AwaitingConfirmation)
            State = RemovalCenterState.PlanReady;
    }

    /// <summary>User explicitly confirmed a destructive action. Valid only from the
    /// confirmation state.</summary>
    public Task ConfirmAsync(CancellationToken cancellationToken = default)
    {
        if (State != RemovalCenterState.AwaitingConfirmation) return Task.CompletedTask;
        return ExecuteAsync(cancellationToken);
    }

    private async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        if (_context is null) return;

        IsBusy = true;
        State = RemovalCenterState.Executing;
        StatusMessage = "Enviando solicitação ao serviço…";

        try
        {
            var request = new RemediationExecutionRequestDto
            {
                CorrelationId = _context.CorrelationId,
                Action = _context.Action,
                TargetKind = _context.TargetKind,
                TargetIdentity = _context.TargetIdentity,
            };

            RemediationExecutionResponseDto? response =
                await _service.ExecuteAsync(request, cancellationToken).ConfigureAwait(false);
            MapResponse(response);
        }
        catch (OperationCanceledException)
        {
            State = RemovalCenterState.Failed;
            ResultMessage = "Operação cancelada antes de uma resposta do serviço.";
        }
        catch (Exception ex)
        {
            State = RemovalCenterState.Failed;
            ResultMessage = $"Falha de comunicação com o serviço: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
            StatusMessage = string.Empty;
        }
    }

    private void MapResponse(RemediationExecutionResponseDto? response)
    {
        if (response is null)
        {
            State = RemovalCenterState.Failed;
            ResultMessage = "O serviço não retornou uma resposta de remediação (IPC indisponível).";
            return;
        }

        Steps = response.Actions
            .Select(a => new RemovalCenterStepView(
                a.Action.ToString(), a.TargetIdentity, a.Outcome, a.Succeeded, a.NoChange, a.Reason))
            .ToArray();
        RequiresReboot = response.RequiresReboot;
        RequiresVerification = response.RequiresVerification;

        if (!response.Authorized || response.Authorization != RemediationIpcAuthorization.Authorized)
        {
            State = RemovalCenterState.Failed;
            ResultMessage = DescribeDenial(response);
            return;
        }

        if (response.RequiresReboot)
        {
            State = RemovalCenterState.RebootRequired;
            ResultMessage = "A remoção termina após reiniciar o computador. Nada é reiniciado automaticamente.";
            return;
        }

        if (response.RequiresVerification)
        {
            State = RemovalCenterState.VerificationNeeded;
            ResultMessage = "Remediação aplicada; verificação pós-remediação pendente.";
            return;
        }

        bool allSucceeded = response.Actions.Count > 0 && response.Actions.All(a => a.Succeeded);
        if (allSucceeded)
        {
            State = RemovalCenterState.Succeeded;
            ResultMessage = "Ameaça remediada.";
        }
        else
        {
            State = RemovalCenterState.Failed;
            ResultMessage = "A remediação não foi concluída integralmente. Verifique os passos e o estado restante.";
        }
    }

    private static string DescribeDenial(RemediationExecutionResponseDto response) => response.Authorization switch
    {
        RemediationIpcAuthorization.DeniedByPolicy => $"A política não autorizou a ação ({response.DenialReason}).",
        RemediationIpcAuthorization.ConsentMissing => "Confirmação obrigatória ainda não emitida pelo serviço para esta ação.",
        RemediationIpcAuthorization.ConsentExpired => "A confirmação expirou; refaça a confirmação.",
        RemediationIpcAuthorization.ConsentMismatch => "A confirmação não corresponde exatamente a esta ação e alvo.",
        RemediationIpcAuthorization.ConsentTierInsufficient => "Confirmação insuficiente para o nível exigido pela política.",
        RemediationIpcAuthorization.ConsentTierMismatch => "Nível de confirmação não corresponde ao exigido pela política.",
        _ => string.IsNullOrWhiteSpace(response.Message) ? "A remediação não foi autorizada." : response.Message,
    };

    private static bool IsDestructiveAction(RemediationIpcActionKind action) => action switch
    {
        RemediationIpcActionKind.Unknown => false,
        RemediationIpcActionKind.QuarantineFile => false,
        RemediationIpcActionKind.PostRemediationVerification => false,
        _ => true,
    };

    private static string DescribeAction(RemediationIpcActionKind action) => action switch
    {
        RemediationIpcActionKind.QuarantineFile => "Colocar em quarentena (reversível)",
        RemediationIpcActionKind.DeleteFile => "Excluir arquivo (após quarentena)",
        RemediationIpcActionKind.KillProcessTree => "Encerrar árvore de processos",
        RemediationIpcActionKind.DisablePersistence => "Desabilitar persistência",
        RemediationIpcActionKind.StopAndDisableService => "Parar e desabilitar serviço",
        RemediationIpcActionKind.RemoveRegistryAutorun => "Remover autorun do registro",
        RemediationIpcActionKind.RemoveScheduledTask => "Remover tarefa agendada",
        RemediationIpcActionKind.RemoveStartupFolderEntry => "Remover item da pasta de inicialização",
        RemediationIpcActionKind.HandleLockedFile => "Tratar arquivo bloqueado (pode exigir reinício)",
        RemediationIpcActionKind.RemoveBrowserExtension => "Remover extensão do navegador",
        RemediationIpcActionKind.CleanDroppedPayload => "Limpar payload descartado",
        RemediationIpcActionKind.RestoreHijackedSetting => "Restaurar configuração sequestrada",
        RemediationIpcActionKind.PostRemediationVerification => "Verificar remediação",
        _ => "Ação desconhecida",
    };

    private void RaiseCommandState()
    {
        OnPropertyChanged(nameof(CanProceed));
        OnPropertyChanged(nameof(CanConfirm));
        OnPropertyChanged(nameof(CanCancelConfirmation));
    }

    private void RaiseContextDerived()
    {
        OnPropertyChanged(nameof(Title));
        OnPropertyChanged(nameof(RiskText));
        OnPropertyChanged(nameof(TargetText));
        OnPropertyChanged(nameof(RecommendedActionText));
        OnPropertyChanged(nameof(IsDestructive));
        OnPropertyChanged(nameof(RequiresConfirmation));
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
