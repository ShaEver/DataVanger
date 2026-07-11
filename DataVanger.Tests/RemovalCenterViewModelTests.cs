using System;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Shared.Remediation;
using DataVanger.ViewModels;
using Xunit;

// Phase 05 — Removal Center ViewModel. WPF-free consent/visualization surface:
// it builds a request DTO, drives execution through the IPC gateway only, and
// renders the service response. It never executes locally and never lowers a
// policy confirmation requirement.
public class RemovalCenterViewModelTests
{
    [Fact]
    public void Prepare_MovesToPlanReady_AndExposesContext()
    {
        var vm = new RemovalCenterViewModel(new FakeService(Authorized()));

        vm.Prepare(Context(RemediationIpcActionKind.QuarantineFile));

        Assert.Equal(RemovalCenterState.PlanReady, vm.State);
        Assert.Equal("evil.exe", vm.Title);
        Assert.Equal(@"C:\temp\evil.exe", vm.TargetText);
        Assert.False(string.IsNullOrEmpty(vm.RecommendedActionText));
        Assert.True(vm.CanProceed);
    }

    [Fact]
    public void DestructiveAction_RequiresConfirmation_WithSafeDefault()
    {
        var vm = new RemovalCenterViewModel(new FakeService(Authorized()));
        vm.Prepare(Context(RemediationIpcActionKind.DeleteFile));

        Assert.True(vm.IsDestructive);
        Assert.True(vm.RequiresConfirmation);
        Assert.True(vm.SafeDefaultIsCancel);
    }

    [Fact]
    public void QuarantineAction_IsNotDestructive()
    {
        var vm = new RemovalCenterViewModel(new FakeService(Authorized()));
        vm.Prepare(Context(RemediationIpcActionKind.QuarantineFile));

        Assert.False(vm.IsDestructive);
        Assert.False(vm.RequiresConfirmation);
    }

    [Fact]
    public async Task ProceedAsync_DestructiveAction_AwaitsConfirmation_WithoutExecuting()
    {
        var fake = new FakeService(Authorized());
        var vm = new RemovalCenterViewModel(fake);
        vm.Prepare(Context(RemediationIpcActionKind.DeleteFile));

        await vm.ProceedAsync();

        Assert.Equal(RemovalCenterState.AwaitingConfirmation, vm.State);
        Assert.Equal(0, fake.Calls);
        Assert.True(vm.CanConfirm);
        Assert.True(vm.CanCancelConfirmation);
    }

    [Fact]
    public async Task ProceedAsync_NonDestructive_ExecutesImmediately()
    {
        var fake = new FakeService(Authorized());
        var vm = new RemovalCenterViewModel(fake);
        vm.Prepare(Context(RemediationIpcActionKind.QuarantineFile));

        await vm.ProceedAsync();

        Assert.Equal(1, fake.Calls);
        Assert.Equal(RemovalCenterState.Succeeded, vm.State);
        Assert.Equal(RemediationIpcActionKind.QuarantineFile, fake.LastRequest!.Action);
    }

    [Fact]
    public async Task CancelConfirmation_ReturnsToPlanReady_WithoutExecuting()
    {
        var fake = new FakeService(Authorized());
        var vm = new RemovalCenterViewModel(fake);
        vm.Prepare(Context(RemediationIpcActionKind.DeleteFile));
        await vm.ProceedAsync();

        vm.CancelConfirmation();

        Assert.Equal(RemovalCenterState.PlanReady, vm.State);
        Assert.Equal(0, fake.Calls);
    }

    [Fact]
    public async Task ConfirmAsync_AfterConfirmation_Executes()
    {
        var fake = new FakeService(Authorized());
        var vm = new RemovalCenterViewModel(fake);
        vm.Prepare(Context(RemediationIpcActionKind.DeleteFile));
        await vm.ProceedAsync();

        await vm.ConfirmAsync();

        Assert.Equal(1, fake.Calls);
        Assert.Equal(RemovalCenterState.Succeeded, vm.State);
    }

    [Fact]
    public async Task ConfirmAsync_WithoutPriorConfirmationState_DoesNothing()
    {
        var fake = new FakeService(Authorized());
        var vm = new RemovalCenterViewModel(fake);
        vm.Prepare(Context(RemediationIpcActionKind.DeleteFile));

        await vm.ConfirmAsync();

        Assert.Equal(0, fake.Calls);
        Assert.Equal(RemovalCenterState.PlanReady, vm.State);
    }

    [Fact]
    public async Task DeniedByPolicy_MapsToFailed_WithReason()
    {
        var fake = new FakeService(Denied(RemediationIpcAuthorization.DeniedByPolicy, "HighRiskRequiresConfirmedMalwareForRemoval"));
        var vm = new RemovalCenterViewModel(fake);
        vm.Prepare(Context(RemediationIpcActionKind.QuarantineFile));

        await vm.ProceedAsync();

        Assert.Equal(RemovalCenterState.Failed, vm.State);
        Assert.Contains("política", vm.ResultMessage);
    }

    [Fact]
    public async Task ConsentMissing_MapsToFailed()
    {
        var fake = new FakeService(Denied(RemediationIpcAuthorization.ConsentMissing));
        var vm = new RemovalCenterViewModel(fake);
        vm.Prepare(Context(RemediationIpcActionKind.QuarantineFile));

        await vm.ProceedAsync();

        Assert.Equal(RemovalCenterState.Failed, vm.State);
        Assert.False(string.IsNullOrWhiteSpace(vm.ResultMessage));
    }

    [Fact]
    public async Task RebootRequired_MapsToRebootRequired()
    {
        var fake = new FakeService(Authorized(reboot: true));
        var vm = new RemovalCenterViewModel(fake);
        vm.Prepare(Context(RemediationIpcActionKind.QuarantineFile));

        await vm.ProceedAsync();

        Assert.Equal(RemovalCenterState.RebootRequired, vm.State);
        Assert.True(vm.RequiresReboot);
    }

    [Fact]
    public async Task VerificationRequired_MapsToVerificationNeeded()
    {
        var fake = new FakeService(Authorized(verify: true));
        var vm = new RemovalCenterViewModel(fake);
        vm.Prepare(Context(RemediationIpcActionKind.QuarantineFile));

        await vm.ProceedAsync();

        Assert.Equal(RemovalCenterState.VerificationNeeded, vm.State);
        Assert.True(vm.RequiresVerification);
    }

    [Fact]
    public async Task NullResponse_IpcFailure_MapsToFailed()
    {
        var fake = new FakeService(response: null);
        var vm = new RemovalCenterViewModel(fake);
        vm.Prepare(Context(RemediationIpcActionKind.QuarantineFile));

        await vm.ProceedAsync();

        Assert.Equal(RemovalCenterState.Failed, vm.State);
        Assert.Contains("IPC", vm.ResultMessage);
    }

    [Fact]
    public async Task ServiceThrows_MapsToFailed()
    {
        var fake = new FakeService(Authorized(), throwError: true);
        var vm = new RemovalCenterViewModel(fake);
        vm.Prepare(Context(RemediationIpcActionKind.QuarantineFile));

        await vm.ProceedAsync();

        Assert.Equal(RemovalCenterState.Failed, vm.State);
        Assert.False(string.IsNullOrWhiteSpace(vm.ResultMessage));
    }

    [Fact]
    public async Task AuthorizedAllStepsSucceeded_MapsToSucceeded()
    {
        var fake = new FakeService(Authorized());
        var vm = new RemovalCenterViewModel(fake);
        vm.Prepare(Context(RemediationIpcActionKind.QuarantineFile));

        await vm.ProceedAsync();

        Assert.Equal(RemovalCenterState.Succeeded, vm.State);
        Assert.Single(vm.Steps);
    }

    [Fact]
    public void Prepare_WhenServiceUnavailable_DisablesProceed_AndShowsHonestOfflineState()
    {
        var vm = new RemovalCenterViewModel(new FakeService(Authorized(), available: false));

        vm.Prepare(Context(RemediationIpcActionKind.QuarantineFile));

        Assert.Equal(RemovalCenterState.PlanReady, vm.State);
        Assert.False(vm.CanProceed);
        Assert.Contains("indisponível", vm.ResultMessage);
        Assert.DoesNotContain("remediada", vm.ResultMessage);
    }

    [Fact]
    public async Task ProceedAsync_WhenServiceUnavailable_FailsClosed_WithoutSuccess()
    {
        var fake = new FakeService(Authorized(), available: false);
        var vm = new RemovalCenterViewModel(fake);
        vm.Prepare(Context(RemediationIpcActionKind.QuarantineFile));

        await vm.ProceedAsync();

        Assert.Equal(RemovalCenterState.Failed, vm.State);
        Assert.Equal(0, fake.Calls);
        Assert.Contains("indisponível", vm.ResultMessage);
        Assert.DoesNotContain("remediada", vm.ResultMessage);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static RemovalCenterThreatContext Context(
        RemediationIpcActionKind action,
        RemediationIpcTargetKind targetKind = RemediationIpcTargetKind.File,
        string target = @"C:\temp\evil.exe")
        => new()
        {
            CorrelationId = Guid.NewGuid().ToString("N"),
            Action = action,
            TargetKind = targetKind,
            TargetIdentity = target,
            Title = "evil.exe",
            RiskText = "Crítico",
        };

    private static RemediationExecutionResponseDto Authorized(bool reboot = false, bool verify = false)
        => new()
        {
            Authorized = true,
            Authorization = RemediationIpcAuthorization.Authorized,
            PolicyOutcome = RemediationIpcPolicyOutcome.Allowed,
            RequiresReboot = reboot,
            RequiresVerification = verify,
            Actions = new[]
            {
                new RemediationActionExecutionResultDto
                {
                    Action = RemediationIpcActionKind.QuarantineFile,
                    TargetKind = RemediationIpcTargetKind.File,
                    TargetIdentity = @"C:\temp\evil.exe",
                    Outcome = "Succeeded",
                    Succeeded = true,
                },
            },
        };

    private static RemediationExecutionResponseDto Denied(RemediationIpcAuthorization auth, string reason = "")
        => new()
        {
            Authorized = false,
            Authorization = auth,
            PolicyOutcome = RemediationIpcPolicyOutcome.Blocked,
            DenialReason = reason,
            Actions = Array.Empty<RemediationActionExecutionResultDto>(),
        };

    private sealed class FakeService : IRemovalCenterService
    {
        private readonly RemediationExecutionResponseDto? _response;
        private readonly bool _throw;

        public FakeService(RemediationExecutionResponseDto? response, bool available = true, bool throwError = false)
        {
            _response = response;
            IsAvailable = available;
            _throw = throwError;
        }

        public bool IsAvailable { get; }
        public int Calls { get; private set; }
        public RemediationExecutionRequestDto? LastRequest { get; private set; }

        public Task<RemediationExecutionResponseDto?> ExecuteAsync(
            RemediationExecutionRequestDto request,
            CancellationToken cancellationToken = default)
        {
            Calls++;
            LastRequest = request;
            if (_throw) throw new InvalidOperationException("pipe broken");
            return Task.FromResult(_response);
        }
    }
}
