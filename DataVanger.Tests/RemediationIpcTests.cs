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
using DataVanger.Service.Ipc;
using DataVanger.Shared.Ipc;
using DataVanger.Shared.Quarantine;
using DataVanger.Shared.Remediation;
using Xunit;
using EngineActionKind = DataVanger.Engine.Remediation.RemediationActionKind;

public class RemediationIpcTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 13, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid Correlation = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    [Fact]
    public void SharedRemediationDtos_DoNotReferenceEngineAssembly()
    {
        var references = typeof(RemediationExecutionRequestDto)
            .Assembly
            .GetReferencedAssemblies()
            .Select(a => a.Name)
            .ToArray();

        Assert.DoesNotContain("DataVanger.Engine", references);
    }

    [Fact]
    public void CommandCatalog_AllowsOnlySharedRemediationCommand()
    {
        Assert.True(DataVangerCommandCatalog.IsAllowed(DataVangerCommandType.ExecuteRemediationAction));
        Assert.Equal(DataVangerCommandCategory.Remediation,
            DataVangerCommandCatalog.CategoryOf(DataVangerCommandType.ExecuteRemediationAction));
    }

    [Fact]
    public async Task MalformedDto_IsRejected()
    {
        var spy = new SpyRemediationExecutor();
        var router = Router(spy);
        var request = DataVangerRequest.Create(DataVangerCommandType.ExecuteRemediationAction, "{not-json");

        var response = await router.HandleAsync(request);

        Assert.False(response.Success);
        Assert.Equal(IpcStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("MalformedRemediationRequest", response.ErrorCode);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task UnknownRemediationAction_IsRejected()
    {
        var spy = new SpyRemediationExecutor();
        var dto = ValidDto() with { Action = (RemediationIpcActionKind)9999 };

        var response = await Router(spy).HandleAsync(Request(dto));

        Assert.False(response.Success);
        Assert.Equal(IpcStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task ClientSuppliedThreatBand_IsIgnored_ServerContextAuthorizes()
    {
        var spy = new SpyRemediationExecutor();
        var dto = ValidDto() with { ThreatBand = (RemediationIpcThreatBand)9999 };

        var response = await Router(spy).HandleAsync(Request(dto));

        Assert.True(response.Success);
        Assert.Equal(1, spy.Calls);
    }

    [Fact]
    public async Task RequestWithoutConsent_IsRejected_WhenConsentIsRequired()
    {
        var spy = new SpyRemediationExecutor();
        var dto = ValidDto() with
        {
            Action = RemediationIpcActionKind.DeleteFile,
            ThreatBand = RemediationIpcThreatBand.ConfirmedMalware,
            HasConfirmedEvidence = true,
            Consent = null,
        };

        var response = await Router(spy).HandleAsync(Request(dto));
        var payload = Payload(response);

        Assert.False(response.Success);
        Assert.Equal(RemediationIpcAuthorization.ConsentMissing, payload.Authorization);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task ClientCannotSpoofConfirmedMalware()
    {
        var spy = new SpyRemediationExecutor();
        var contexts = ContextStore(band: QuarantineThreatClassification.HighRisk, confirmed: false);
        var dto = DestructiveDto(Consent(RemediationIpcActionKind.DeleteFile, @"C:\temp\evil.exe",
            RemediationIpcConfirmationTier.UserConfirmation)) with
        {
            ThreatBand = RemediationIpcThreatBand.ConfirmedMalware,
            HasConfirmedEvidence = true,
        };

        var response = await Router(spy, contexts: contexts).HandleAsync(Request(dto));

        Assert.Equal(RemediationIpcAuthorization.DeniedByPolicy, Payload(response).Authorization);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task ClientCannotSpoofConfirmedEvidence()
    {
        var spy = new SpyRemediationExecutor();
        var contexts = ContextStore(band: QuarantineThreatClassification.ConfirmedMalware, confirmed: false);
        var dto = DestructiveDto(Consent(RemediationIpcActionKind.DeleteFile, @"C:\temp\evil.exe",
            RemediationIpcConfirmationTier.UserConfirmation)) with
        {
            ThreatBand = RemediationIpcThreatBand.ConfirmedMalware,
            HasConfirmedEvidence = true,
        };

        var response = await Router(spy, contexts: contexts).HandleAsync(Request(dto));

        Assert.Equal(RemediationIpcAuthorization.DeniedByPolicy, Payload(response).Authorization);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task ClientCannotForgeConsentToken()
    {
        var spy = new SpyRemediationExecutor();
        var dto = DestructiveDto(Consent(RemediationIpcActionKind.DeleteFile, @"C:\temp\evil.exe",
            RemediationIpcConfirmationTier.UserConfirmation));

        var response = await Router(spy).HandleAsync(Request(dto));

        Assert.Equal(RemediationIpcAuthorization.ConsentMissing, Payload(response).Authorization);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task MissingServerSideContext_FailsClosed()
    {
        var spy = new SpyRemediationExecutor();

        var response = await Router(spy, contexts: new RemediationServerContextStore())
            .HandleAsync(Request(ValidDto()));

        Assert.False(response.Success);
        Assert.Equal("RemediationContextMissing", response.ErrorCode);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task MismatchedServerSideContext_FailsClosed()
    {
        var spy = new SpyRemediationExecutor();
        var contexts = ContextStore(target: FileTarget(@"C:\temp\other.exe"));

        var response = await Router(spy, contexts: contexts).HandleAsync(Request(ValidDto()));

        Assert.False(response.Success);
        Assert.Equal("RemediationContextMissing", response.ErrorCode);
        Assert.Equal(0, spy.Calls);
    }

    [Theory]
    [InlineData("action")]
    [InlineData("target")]
    [InlineData("correlation")]
    public async Task ServerIssuedConsentForAnotherBinding_DoesNotAuthorize(string mismatch)
    {
        var spy = new SpyRemediationExecutor();
        var contexts = ContextStore();
        var target = FileTarget();

        switch (mismatch)
        {
            case "action":
                contexts.IssueConsent(CorrelationId(), EngineActionKind.QuarantineFile, target,
                    ConfirmationRequirement.UserConfirmation, Now, TimeSpan.FromMinutes(5));
                break;
            case "target":
                var otherTarget = FileTarget(@"C:\temp\other.exe");
                contexts.Register(new RemediationServerContext
                {
                    CorrelationId = CorrelationId(),
                    Target = otherTarget,
                    ThreatBand = QuarantineThreatClassification.ConfirmedMalware,
                    HasConfirmedEvidence = true,
                });
                contexts.IssueConsent(CorrelationId(), EngineActionKind.DeleteFile, otherTarget,
                    ConfirmationRequirement.UserConfirmation, Now, TimeSpan.FromMinutes(5));
                break;
            case "correlation":
                var otherCorrelation = new RemediationCorrelationId(
                    Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
                contexts.Register(new RemediationServerContext
                {
                    CorrelationId = otherCorrelation,
                    Target = target,
                    ThreatBand = QuarantineThreatClassification.ConfirmedMalware,
                    HasConfirmedEvidence = true,
                });
                contexts.IssueConsent(otherCorrelation, EngineActionKind.DeleteFile, target,
                    ConfirmationRequirement.UserConfirmation, Now, TimeSpan.FromMinutes(5));
                break;
        }

        var response = await Router(spy, contexts: contexts)
            .HandleAsync(Request(DestructiveDto(consent: null)));

        Assert.Equal(RemediationIpcAuthorization.ConsentMissing, Payload(response).Authorization);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task ExpiredConsent_IsRejected()
    {
        var spy = new SpyRemediationExecutor();
        var contexts = ContextStore();
        contexts.IssueConsent(CorrelationId(), EngineActionKind.DeleteFile, FileTarget(),
            ConfirmationRequirement.UserConfirmation, Now.AddMinutes(-10), TimeSpan.FromMinutes(5));
        var dto = DestructiveDto(consent: null);

        var response = await Router(spy, contexts: contexts).HandleAsync(Request(dto));

        Assert.Equal(RemediationIpcAuthorization.ConsentExpired, Payload(response).Authorization);
        Assert.Equal(0, spy.Calls);
    }

    [Theory]
    [InlineData("action")]
    [InlineData("target")]
    [InlineData("correlation")]
    public async Task ClientCannotReuseConsent_ForAnotherBinding(string mismatch)
    {
        var spy = new SpyRemediationExecutor();
        var consent = Consent(RemediationIpcActionKind.DeleteFile, @"C:\temp\evil.exe",
            RemediationIpcConfirmationTier.UserConfirmation);

        consent = mismatch switch
        {
            "action" => consent with { Action = RemediationIpcActionKind.KillProcessTree, TargetKind = RemediationIpcTargetKind.Process, TargetIdentity = "1234" },
            "target" => consent with { TargetIdentity = @"C:\temp\other.exe" },
            "correlation" => consent with { CorrelationId = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").ToString("N") },
            _ => consent,
        };

        var response = await Router(spy).HandleAsync(Request(DestructiveDto(consent)));

        Assert.Equal(RemediationIpcAuthorization.ConsentMissing, Payload(response).Authorization);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task WeakerConsentTier_IsRejected()
    {
        var spy = new SpyRemediationExecutor();
        var target = new RemediationTarget(RemediationTargetKind.Service, "EvilSvc");
        var contexts = ContextStore(target);
        contexts.IssueConsent(CorrelationId(), EngineActionKind.StopAndDisableService, target,
            ConfirmationRequirement.UserConfirmation, Now, TimeSpan.FromMinutes(5));
        var dto = ValidDto() with
        {
            Action = RemediationIpcActionKind.StopAndDisableService,
            TargetKind = RemediationIpcTargetKind.Service,
            TargetIdentity = "EvilSvc",
            ThreatBand = RemediationIpcThreatBand.ConfirmedMalware,
            HasConfirmedEvidence = true,
            Consent = Consent(RemediationIpcActionKind.StopAndDisableService, "EvilSvc",
                RemediationIpcConfirmationTier.UserConfirmation) with { TargetKind = RemediationIpcTargetKind.Service },
        };

        var response = await Router(spy, contexts: contexts).HandleAsync(Request(dto));

        Assert.Equal(RemediationIpcAuthorization.ConsentTierInsufficient, Payload(response).Authorization);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task OversizedPayload_IsRejectedBeforeDispatch()
    {
        var spy = new SpyRemediationExecutor();
        var options = new IpcOptions { MaxMessageBytes = 512 };
        var router = Router(spy, options: options);
        var request = new DataVangerRequest
        {
            CommandType = DataVangerCommandType.ExecuteRemediationAction,
            PayloadJson = new string('x', options.MaxMessageBytes + 1),
        };

        var response = await router.HandleAsync(request);

        Assert.False(response.Success);
        Assert.Equal(IpcStatusCode.PayloadTooLarge, response.StatusCode);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task Handler_CannotBypassExecutionGate_ForAuthorizedRequest()
    {
        var spy = new SpyRemediationExecutor();
        var dto = ValidDto();

        var response = await Router(spy).HandleAsync(Request(dto));

        Assert.True(response.Success);
        Assert.Equal(1, spy.Calls);
        Assert.Single(spy.LastPermits!);
        Assert.Equal(DataVanger.Engine.Remediation.RemediationActionKind.QuarantineFile, spy.LastPermits![0].Action);
        Assert.Equal(spy.LastPlan!.CorrelationId, spy.LastPermits![0].CorrelationId);
        Assert.Equal(spy.LastPlan.Steps[0].Action.Target.MatchKey, spy.LastPermits![0].TargetMatchKey);
    }

    [Fact]
    public async Task ConfirmedMalwareDestructiveRemoval_ExecutesOnlyWithGatePermits()
    {
        var spy = new SpyRemediationExecutor();
        var contexts = ContextStore();
        contexts.IssueConsent(CorrelationId(), EngineActionKind.DeleteFile, FileTarget(),
            ConfirmationRequirement.UserConfirmation, Now, TimeSpan.FromMinutes(5));
        var dto = DestructiveDto(Consent(RemediationIpcActionKind.DeleteFile, @"C:\temp\evil.exe",
            RemediationIpcConfirmationTier.UserConfirmation));

        var response = await Router(spy, contexts: contexts).HandleAsync(Request(dto));

        Assert.True(response.Success);
        Assert.Equal(1, spy.Calls);
        Assert.Equal(2, spy.LastPlan!.Steps.Count);
        Assert.Equal(2, spy.LastPermits!.Count);
        Assert.Contains(spy.LastPermits, p => p.Action == EngineActionKind.QuarantineFile);
        Assert.Contains(spy.LastPermits, p => p.Action == EngineActionKind.DeleteFile);
    }

    [Fact]
    public async Task HighRiskDestructiveRemoval_IsBlocked_EvenWithSpoofedConsent()
    {
        var spy = new SpyRemediationExecutor();
        var contexts = ContextStore(band: QuarantineThreatClassification.HighRisk, confirmed: false);
        var dto = DestructiveDto(Consent(RemediationIpcActionKind.DeleteFile, @"C:\temp\evil.exe",
            RemediationIpcConfirmationTier.UserConfirmation)) with
        {
            ThreatBand = RemediationIpcThreatBand.ConfirmedMalware,
            HasConfirmedEvidence = true,
        };

        var response = await Router(spy, contexts: contexts).HandleAsync(Request(dto));

        Assert.Equal(RemediationIpcAuthorization.DeniedByPolicy, Payload(response).Authorization);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task HeuristicOnlyDetection_CannotTriggerDestructiveRemediation()
    {
        var spy = new SpyRemediationExecutor();
        var contexts = ContextStore(heuristicOnly: true);
        var dto = DestructiveDto(Consent(RemediationIpcActionKind.DeleteFile, @"C:\temp\evil.exe",
            RemediationIpcConfirmationTier.UserConfirmation)) with
        {
            EvidenceIsHeuristicOnly = false,
        };

        var response = await Router(spy, contexts: contexts).HandleAsync(Request(dto));

        Assert.Equal(RemediationIpcAuthorization.DeniedByPolicy, Payload(response).Authorization);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task CleanBand_Action_IsDeniedByPolicy()
    {
        var spy = new SpyRemediationExecutor();
        var contexts = ContextStore(band: QuarantineThreatClassification.Clean, confirmed: false);
        var dto = ValidDto() with { ThreatBand = RemediationIpcThreatBand.ConfirmedMalware };

        var response = await Router(spy, contexts: contexts).HandleAsync(Request(dto));

        Assert.False(response.Success);
        Assert.Equal(RemediationIpcAuthorization.DeniedByPolicy, Payload(response).Authorization);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task SuspectBand_DestructiveAction_IsDeniedByPolicy()
    {
        var spy = new SpyRemediationExecutor();
        var contexts = ContextStore(band: QuarantineThreatClassification.Suspect, confirmed: false);
        var dto = DestructiveDto(Consent(RemediationIpcActionKind.DeleteFile, @"C:\temp\evil.exe",
            RemediationIpcConfirmationTier.UserConfirmation)) with
        {
            ThreatBand = RemediationIpcThreatBand.ConfirmedMalware,
            HasConfirmedEvidence = true,
        };

        var response = await Router(spy, contexts: contexts).HandleAsync(Request(dto));

        Assert.Equal(RemediationIpcAuthorization.DeniedByPolicy, Payload(response).Authorization);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task SystemFile_ConfirmedMalwareQuarantine_IsNotAutomatic_RequiresConsent()
    {
        // A system-file remediation may never run automatically: even a
        // ConfirmedMalware+confirmed quarantine requires explicit consent.
        var spy = new SpyRemediationExecutor();
        var contexts = ContextStore(isSystemFile: true);
        var dto = ValidDto() with { IsSystemFile = false };

        var response = await Router(spy, contexts: contexts).HandleAsync(Request(dto));

        Assert.Equal(RemediationIpcAuthorization.ConsentMissing, Payload(response).Authorization);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task UnknownTargetKind_IsRejected()
    {
        var spy = new SpyRemediationExecutor();
        var dto = ValidDto() with { TargetKind = (RemediationIpcTargetKind)9999 };

        var response = await Router(spy).HandleAsync(Request(dto));

        Assert.False(response.Success);
        Assert.Equal(IpcStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task TargetKindMismatchedToAction_IsRejected()
    {
        var spy = new SpyRemediationExecutor();
        var dto = ValidDto() with { TargetKind = RemediationIpcTargetKind.Process };

        var response = await Router(spy).HandleAsync(Request(dto));

        Assert.False(response.Success);
        Assert.Equal(IpcStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, spy.Calls);
    }

    private static DataVangerServiceCommandRouter Router(
        SpyRemediationExecutor spy,
        RemediationServerContextStore? contexts = null,
        IpcOptions? options = null)
        => new(new DataVangerServiceCommandContext
        {
            RemediationExecutor = spy,
            RemediationNowUtc = () => Now,
            RemediationContexts = contexts ?? ContextStore(),
        }, options);

    private static DataVangerRequest Request(RemediationExecutionRequestDto dto)
        => DataVangerRequest.Create(
            DataVangerCommandType.ExecuteRemediationAction,
            IpcSerialization.SerializePayload(dto));

    private static RemediationExecutionRequestDto ValidDto()
        => new()
        {
            CorrelationId = Correlation.ToString("N"),
            Action = RemediationIpcActionKind.QuarantineFile,
            TargetKind = RemediationIpcTargetKind.File,
            TargetIdentity = @"C:\temp\evil.exe",
            ThreatBand = RemediationIpcThreatBand.ConfirmedMalware,
            HasConfirmedEvidence = true,
        };

    private static RemediationExecutionRequestDto DestructiveDto(RemediationConsentTokenDto? consent)
        => ValidDto() with
        {
            Action = RemediationIpcActionKind.DeleteFile,
            Consent = consent,
        };

    private static RemediationConsentTokenDto Consent(
        RemediationIpcActionKind action,
        string targetIdentity,
        RemediationIpcConfirmationTier tier)
        => new()
        {
            Action = action,
            TargetKind = RemediationIpcTargetKind.File,
            TargetIdentity = targetIdentity,
            Tier = tier,
            CorrelationId = Correlation.ToString("N"),
            IssuedUtc = Now,
            ExpiresUtc = Now.AddMinutes(5),
        };

    private static RemediationServerContextStore ContextStore(
        RemediationTarget? target = null,
        QuarantineThreatClassification band = QuarantineThreatClassification.ConfirmedMalware,
        bool confirmed = true,
        bool heuristicOnly = false,
        bool isSystemFile = false)
    {
        var store = new RemediationServerContextStore();
        store.Register(new RemediationServerContext
        {
            CorrelationId = CorrelationId(),
            Target = target ?? FileTarget(),
            ThreatBand = band,
            HasConfirmedEvidence = confirmed,
            EvidenceIsHeuristicOnly = heuristicOnly,
            IsSystemFile = isSystemFile,
        });
        return store;
    }

    private static RemediationTarget FileTarget(string path = @"C:\temp\evil.exe")
        => new(RemediationTargetKind.File, path);

    private static RemediationCorrelationId CorrelationId()
        => new(Correlation);

    private static RemediationExecutionResponseDto Payload(DataVangerResponse response)
    {
        Assert.True(IpcSerialization.TryDeserializePayload<RemediationExecutionResponseDto>(
            response.PayloadJson, out var payload));
        return payload!;
    }

    private sealed class SpyRemediationExecutor : IRemediationPlanExecutor
    {
        public int Calls { get; private set; }
        public RemediationPlan? LastPlan { get; private set; }
        public IReadOnlyList<RemediationExecutionPermit>? LastPermits { get; private set; }

        public Task<RemediationExecutionResult> ExecuteAuthorizedAsync(
            RemediationPlan plan,
            IReadOnlyList<RemediationExecutionPermit> permits,
            CancellationToken cancellationToken = default)
        {
            Calls++;
            LastPlan = plan;
            LastPermits = permits.ToArray();
            return Task.FromResult(new RemediationExecutionResult
            {
                CorrelationId = plan.CorrelationId,
                ActionResults = plan.Steps.Select(step => new RemediationActionResult
                {
                    Action = step.Action,
                    Outcome = RemediationOutcome.Succeeded,
                    Reason = "spy execution",
                }).ToArray(),
            });
        }
    }
}
