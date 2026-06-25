using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Planning;
using DataVanger.Engine.Remediation.Policy;
using DataVanger.Engine.Remediation.Results;
using DataVanger.Infrastructure.Ipc;
using DataVanger.Shared.Ipc;
using DataVanger.Shared.Remediation;

namespace DataVanger.Service.Ipc;

internal sealed class RemediationCommandHandler
{
    private readonly DataVangerServiceCommandContext _context;

    public RemediationCommandHandler(DataVangerServiceCommandContext context)
    {
        _context = context;
    }

    public async Task<DataVangerResponse> HandleAsync(DataVangerRequest request, CancellationToken cancellationToken)
    {
        if (request.CommandType != DataVangerCommandType.ExecuteRemediationAction)
            return DataVangerResponse.Error(request.RequestId, IpcStatusCode.Unsupported,
                $"Remediation handler does not support '{request.CommandType}'.", "UnsupportedCommand");

        if (!IpcSerialization.TryDeserializePayload<RemediationExecutionRequestDto>(request.PayloadJson, out var dto) || dto is null)
            return DataVangerResponse.Error(request.RequestId, IpcStatusCode.BadRequest,
                "Malformed remediation request payload.", "MalformedRemediationRequest");

        if (!TryBuildRequest(dto, out var model, out var badRequest))
            return DataVangerResponse.Error(request.RequestId, IpcStatusCode.BadRequest, badRequest, "InvalidRemediationRequest");

        if (!_context.RemediationContexts.TryResolve(model.CorrelationId, model.Target, out var serverContext))
            return MissingServerContext(request, model.CorrelationId);

        var executor = _context.RemediationExecutor;
        if (executor is null)
            return DataVangerResponse.Error(request.RequestId, IpcStatusCode.Unsupported,
                "Remediation execution is not available on this host.", "RemediationUnavailable");

        var policyRequest = serverContext.ToPolicyRequest(model.Action);
        _context.RemediationContexts.TryGetConsent(model.CorrelationId, model.Action, model.Target, out var consent);

        var authorization = Authorize(model.Action, model.Target, policyRequest, consent);
        if (!authorization.IsAuthorized || authorization.Permit is null)
            return NotAuthorized(request, model.CorrelationId, authorization);

        var permits = new List<RemediationExecutionPermit>();
        var builder = new RemediationPlanBuilder();

        if (RequiresFileContainment(model.Action))
        {
            var containment = Authorize(
                RemediationActionKind.QuarantineFile,
                model.Target,
                serverContext.ToPolicyRequest(RemediationActionKind.QuarantineFile),
                ServerConsent(model.CorrelationId, RemediationActionKind.QuarantineFile, model.Target));

            if (!containment.IsAuthorized || containment.Permit is null)
                return NotAuthorized(request, model.CorrelationId, containment);

            permits.Add(containment.Permit);
            AddPlanStep(builder, RemediationActionKind.QuarantineFile, model.Target, containment.Decision);
        }

        permits.Add(authorization.Permit);
        AddPlanStep(builder, model.Action, model.Target, authorization.Decision);

        RemediationPlan plan;
        try
        {
            plan = builder.Build() with { CorrelationId = model.CorrelationId };
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            return DataVangerResponse.Error(request.RequestId, IpcStatusCode.BadRequest,
                $"Invalid remediation plan: {ex.Message}", "InvalidRemediationPlan");
        }

        RemediationExecutionResult result = await executor.ExecuteAuthorizedAsync(plan, permits, cancellationToken).ConfigureAwait(false);
        var payload = ToResponseDto(result, authorization, authorized: true);
        return DataVangerResponse.Ok(request.RequestId, IpcSerialization.SerializePayload(payload), "Remediation command executed.");
    }

    private RemediationConsentToken? ServerConsent(
        RemediationCorrelationId correlationId,
        RemediationActionKind action,
        RemediationTarget target)
    {
        _context.RemediationContexts.TryGetConsent(correlationId, action, target, out var consent);
        return consent;
    }

    private RemediationAuthorizationResult Authorize(
        RemediationActionKind action,
        RemediationTarget target,
        RemediationPolicyRequest request,
        RemediationConsentToken? consent)
        => _context.RemediationGate.Authorize(
            request with { Action = action },
            target.MatchKey,
            consent,
            _context.RemediationNowUtc());

    private static void AddPlanStep(
        RemediationPlanBuilder builder,
        RemediationActionKind action,
        RemediationTarget target,
        RemediationPolicyDecision decision)
    {
        ConfirmationRequirement? confirmationOverride = decision.RequiredConfirmation is
            ConfirmationRequirement.Unspecified or ConfirmationRequirement.None
                ? null
                : decision.RequiredConfirmation;

        builder.Add(action, target, confirmationOverride);
    }

    private static bool RequiresFileContainment(RemediationActionKind action)
        => action is RemediationActionKind.DeleteFile
            or RemediationActionKind.HandleLockedFile
            or RemediationActionKind.CleanDroppedPayload;

    private static DataVangerResponse NotAuthorized(
        DataVangerRequest request,
        RemediationCorrelationId correlationId,
        RemediationAuthorizationResult authorization)
    {
        var payload = ToResponseDto(
            new RemediationExecutionResult
            {
                CorrelationId = correlationId,
                ActionResults = Array.Empty<RemediationActionResult>(),
            },
            authorization,
            authorized: false);

        return new DataVangerResponse
        {
            RequestId = request.RequestId,
            Success = false,
            StatusCode = IpcStatusCode.BadRequest,
            Message = authorization.Reason,
            ErrorCode = "RemediationNotAuthorized",
            PayloadJson = IpcSerialization.SerializePayload(payload),
        };
    }

    private static DataVangerResponse MissingServerContext(
        DataVangerRequest request,
        RemediationCorrelationId correlationId)
    {
        var payload = new RemediationExecutionResponseDto
        {
            CorrelationId = correlationId.ToString(),
            Authorized = false,
            Authorization = RemediationIpcAuthorization.DeniedByPolicy,
            PolicyOutcome = RemediationIpcPolicyOutcome.Blocked,
            RequiredConfirmation = RemediationIpcConfirmationTier.Unknown,
            DenialReason = "MissingServerContext",
            Message = "Missing or mismatched server-side remediation context.",
            Actions = Array.Empty<RemediationActionExecutionResultDto>(),
        };

        return new DataVangerResponse
        {
            RequestId = request.RequestId,
            Success = false,
            StatusCode = IpcStatusCode.BadRequest,
            Message = payload.Message,
            ErrorCode = "RemediationContextMissing",
            PayloadJson = IpcSerialization.SerializePayload(payload),
        };
    }

    private static RemediationExecutionResponseDto ToResponseDto(
        RemediationExecutionResult result,
        RemediationAuthorizationResult authorization,
        bool authorized)
        => new()
        {
            CorrelationId = result.CorrelationId.ToString(),
            Authorized = authorized,
            Authorization = Map(authorization.Authorization),
            PolicyOutcome = Map(authorization.Decision.Outcome),
            RequiredConfirmation = Map(authorization.Decision.RequiredConfirmation),
            DenialReason = authorization.Decision.DenialReason.ToString(),
            Message = authorization.Reason,
            RequiresReboot = result.RequiresReboot,
            RequiresVerification = result.RequiresVerification,
            Actions = result.ActionResults.Select(ToActionDto).ToArray(),
        };

    private static RemediationActionExecutionResultDto ToActionDto(RemediationActionResult result)
        => new()
        {
            Action = Map(result.Action.Kind),
            TargetKind = Map(result.Action.Target.Kind),
            TargetIdentity = result.Action.Target.Identity,
            Outcome = result.Outcome.ToString(),
            Succeeded = result.Succeeded,
            NoChange = result.IsNoChange,
            Reason = result.Reason,
        };

    private static bool TryBuildRequest(
        RemediationExecutionRequestDto dto,
        out ExecutionModel model,
        out string error)
    {
        model = default!;
        error = string.Empty;

        if (!TryParseCorrelation(dto.CorrelationId, out var correlationId))
            return Fail("A non-empty remediation correlation id is required.", out error);

        if (!TryMap(dto.Action, out var action))
            return Fail("Unknown remediation action.", out error);

        if (!TryMap(dto.TargetKind, out var targetKind))
            return Fail("Unknown remediation target kind.", out error);

        if (string.IsNullOrWhiteSpace(dto.TargetIdentity))
            return Fail("Remediation target identity is required.", out error);

        if (targetKind != RemediationActionCatalog.TargetKindOf(action))
            return Fail("Remediation target kind does not match the requested action.", out error);

        if (targetKind == RemediationTargetKind.File && !IpcSecurityPolicy.IsSafePath(dto.TargetIdentity))
            return Fail("Remediation file target path is not structurally safe.", out error);

        RemediationTarget target;
        try
        {
            target = new RemediationTarget(targetKind, dto.TargetIdentity);
        }
        catch (ArgumentException ex)
        {
            return Fail(ex.Message, out error);
        }

        model = new ExecutionModel(
            correlationId,
            action,
            target);
        return true;

        static bool Fail(string message, out string failure)
        {
            failure = message;
            return false;
        }
    }

    private static bool TryParseCorrelation(string? text, out RemediationCorrelationId id)
    {
        id = default;
        if (string.IsNullOrWhiteSpace(text)) return false;
        if (!Guid.TryParse(text, out var guid) || guid == Guid.Empty) return false;
        id = new RemediationCorrelationId(guid);
        return true;
    }

    private static bool TryMap(RemediationIpcActionKind value, out RemediationActionKind mapped)
    {
        mapped = value switch
        {
            RemediationIpcActionKind.KillProcessTree => RemediationActionKind.KillProcessTree,
            RemediationIpcActionKind.QuarantineFile => RemediationActionKind.QuarantineFile,
            RemediationIpcActionKind.DisablePersistence => RemediationActionKind.DisablePersistence,
            RemediationIpcActionKind.StopAndDisableService => RemediationActionKind.StopAndDisableService,
            RemediationIpcActionKind.RemoveRegistryAutorun => RemediationActionKind.RemoveRegistryAutorun,
            RemediationIpcActionKind.RemoveScheduledTask => RemediationActionKind.RemoveScheduledTask,
            RemediationIpcActionKind.RemoveStartupFolderEntry => RemediationActionKind.RemoveStartupFolderEntry,
            RemediationIpcActionKind.DeleteFile => RemediationActionKind.DeleteFile,
            RemediationIpcActionKind.HandleLockedFile => RemediationActionKind.HandleLockedFile,
            RemediationIpcActionKind.RemoveBrowserExtension => RemediationActionKind.RemoveBrowserExtension,
            RemediationIpcActionKind.CleanDroppedPayload => RemediationActionKind.CleanDroppedPayload,
            RemediationIpcActionKind.RestoreHijackedSetting => RemediationActionKind.RestoreHijackedSetting,
            RemediationIpcActionKind.PostRemediationVerification => RemediationActionKind.PostRemediationVerification,
            _ => RemediationActionKind.None,
        };
        return mapped != RemediationActionKind.None;
    }

    private static bool TryMap(RemediationIpcTargetKind value, out RemediationTargetKind mapped)
    {
        mapped = value switch
        {
            RemediationIpcTargetKind.File => RemediationTargetKind.File,
            RemediationIpcTargetKind.Process => RemediationTargetKind.Process,
            RemediationIpcTargetKind.Service => RemediationTargetKind.Service,
            RemediationIpcTargetKind.RegistryValue => RemediationTargetKind.RegistryValue,
            RemediationIpcTargetKind.ScheduledTask => RemediationTargetKind.ScheduledTask,
            RemediationIpcTargetKind.StartupEntry => RemediationTargetKind.StartupEntry,
            RemediationIpcTargetKind.BrowserExtension => RemediationTargetKind.BrowserExtension,
            RemediationIpcTargetKind.SystemSetting => RemediationTargetKind.SystemSetting,
            _ => RemediationTargetKind.None,
        };
        return mapped != RemediationTargetKind.None;
    }

    private static RemediationIpcAuthorization Map(RemediationAuthorization value)
        => value switch
        {
            RemediationAuthorization.Authorized => RemediationIpcAuthorization.Authorized,
            RemediationAuthorization.DeniedByPolicy => RemediationIpcAuthorization.DeniedByPolicy,
            RemediationAuthorization.ConsentMissing => RemediationIpcAuthorization.ConsentMissing,
            RemediationAuthorization.ConsentMismatch => RemediationIpcAuthorization.ConsentMismatch,
            RemediationAuthorization.ConsentExpired => RemediationIpcAuthorization.ConsentExpired,
            RemediationAuthorization.ConsentTierInsufficient => RemediationIpcAuthorization.ConsentTierInsufficient,
            RemediationAuthorization.ConsentTierMismatch => RemediationIpcAuthorization.ConsentTierMismatch,
            _ => RemediationIpcAuthorization.Unknown,
        };

    private static RemediationIpcPolicyOutcome Map(PolicyOutcome value)
        => value switch
        {
            PolicyOutcome.Blocked => RemediationIpcPolicyOutcome.Blocked,
            PolicyOutcome.ReportOnly => RemediationIpcPolicyOutcome.ReportOnly,
            PolicyOutcome.NoAction => RemediationIpcPolicyOutcome.NoAction,
            PolicyOutcome.Allowed => RemediationIpcPolicyOutcome.Allowed,
            _ => RemediationIpcPolicyOutcome.Unknown,
        };

    private static RemediationIpcConfirmationTier Map(ConfirmationRequirement value)
        => value switch
        {
            ConfirmationRequirement.None => RemediationIpcConfirmationTier.None,
            ConfirmationRequirement.UserConfirmation => RemediationIpcConfirmationTier.UserConfirmation,
            ConfirmationRequirement.RebootConsent => RemediationIpcConfirmationTier.RebootConsent,
            ConfirmationRequirement.AdvancedConfirmation => RemediationIpcConfirmationTier.AdvancedConfirmation,
            _ => RemediationIpcConfirmationTier.Unknown,
        };

    private static RemediationIpcActionKind Map(RemediationActionKind value)
        => value switch
        {
            RemediationActionKind.KillProcessTree => RemediationIpcActionKind.KillProcessTree,
            RemediationActionKind.QuarantineFile => RemediationIpcActionKind.QuarantineFile,
            RemediationActionKind.DisablePersistence => RemediationIpcActionKind.DisablePersistence,
            RemediationActionKind.StopAndDisableService => RemediationIpcActionKind.StopAndDisableService,
            RemediationActionKind.RemoveRegistryAutorun => RemediationIpcActionKind.RemoveRegistryAutorun,
            RemediationActionKind.RemoveScheduledTask => RemediationIpcActionKind.RemoveScheduledTask,
            RemediationActionKind.RemoveStartupFolderEntry => RemediationIpcActionKind.RemoveStartupFolderEntry,
            RemediationActionKind.DeleteFile => RemediationIpcActionKind.DeleteFile,
            RemediationActionKind.HandleLockedFile => RemediationIpcActionKind.HandleLockedFile,
            RemediationActionKind.RemoveBrowserExtension => RemediationIpcActionKind.RemoveBrowserExtension,
            RemediationActionKind.CleanDroppedPayload => RemediationIpcActionKind.CleanDroppedPayload,
            RemediationActionKind.RestoreHijackedSetting => RemediationIpcActionKind.RestoreHijackedSetting,
            RemediationActionKind.PostRemediationVerification => RemediationIpcActionKind.PostRemediationVerification,
            _ => RemediationIpcActionKind.Unknown,
        };

    private static RemediationIpcTargetKind Map(RemediationTargetKind value)
        => value switch
        {
            RemediationTargetKind.File => RemediationIpcTargetKind.File,
            RemediationTargetKind.Process => RemediationIpcTargetKind.Process,
            RemediationTargetKind.Service => RemediationIpcTargetKind.Service,
            RemediationTargetKind.RegistryValue => RemediationIpcTargetKind.RegistryValue,
            RemediationTargetKind.ScheduledTask => RemediationIpcTargetKind.ScheduledTask,
            RemediationTargetKind.StartupEntry => RemediationIpcTargetKind.StartupEntry,
            RemediationTargetKind.BrowserExtension => RemediationIpcTargetKind.BrowserExtension,
            RemediationTargetKind.SystemSetting => RemediationIpcTargetKind.SystemSetting,
            _ => RemediationIpcTargetKind.Unknown,
        };

    private sealed record ExecutionModel(
        RemediationCorrelationId CorrelationId,
        RemediationActionKind Action,
        RemediationTarget Target);
}
