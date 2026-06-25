using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Infrastructure.Ipc;
using DataVanger.Shared.Ipc;
using Xunit;

// Phase 02B — IPC ACL hardening.
//
// These tests prove TWO things and are careful not to overclaim a third:
//   1. The connection-level ACL model is least-privilege: default-deny, no
//      Everyone/Network/Anonymous grant, current user + Local System allowed,
//      configured principals added safely, invalid principals ignored.
//   2. Payload validation (IpcSecurityPolicy) is unchanged — ACL hardening is
//      defense-in-depth, not a replacement.
//
// They do NOT claim that an *unauthorized* Windows principal is rejected: that
// requires a second Windows account and is documented as manual Windows
// validation in the phase report. The authorized round-trip below proves a
// legitimate local client is NOT blocked by the ACL.
//
// ACL assertions are Windows-guarded; the OS-neutral assertions (options,
// policy regression) run everywhere. Filter: --filter "FullyQualifiedName~Ipc".
public class IpcAclTests
{
    // ── Options: safe defaults + configurability (OS-neutral) ───────────────

    [Fact]
    public void IpcOptions_Default_HardensAcl_AndHasNoExtraPrincipals()
    {
        var options = IpcOptions.Default;
        Assert.True(options.HardenPipeAcl);
        Assert.NotNull(options.AllowedPrincipalSids);
        Assert.Empty(options.AllowedPrincipalSids);
    }

    [Fact]
    public void IpcOptions_AllowedPrincipals_AreConfigurable()
    {
        var options = new IpcOptions
        {
            AllowedPrincipalSids = new[] { "S-1-5-32-545" },
            HardenPipeAcl = false,
        };
        Assert.False(options.HardenPipeAcl);
        Assert.Single(options.AllowedPrincipalSids);
        Assert.Equal("S-1-5-32-545", options.AllowedPrincipalSids[0]);
    }

    // ── ACL model (Windows-only) ────────────────────────────────────────────

    [WindowsOnlyFact]
    [SupportedOSPlatform("windows")]
    public void DefaultAcl_DoesNotGrantEveryoneOrAnonymous()
    {
        var rules = AllowRules(IpcPipeSecurity.Build(IpcOptions.Default));

        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        var anonymous = new SecurityIdentifier(WellKnownSidType.AnonymousSid, null);

        Assert.DoesNotContain(rules, r => r.IdentityReference.Equals(everyone));
        Assert.DoesNotContain(rules, r => r.IdentityReference.Equals(anonymous));
    }

    [WindowsOnlyFact]
    [SupportedOSPlatform("windows")]
    public void DefaultAcl_DeniesNetworkLogon()
    {
        var security = IpcPipeSecurity.Build(IpcOptions.Default);
        var network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);

        var denyRules = security
            .GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>()
            .Where(r => r.AccessControlType == AccessControlType.Deny)
            .ToList();

        Assert.Contains(denyRules, r => r.IdentityReference.Equals(network));
        // And the Network SID must not appear as an allow grant.
        Assert.DoesNotContain(AllowRules(security), r => r.IdentityReference.Equals(network));
    }

    [WindowsOnlyFact]
    [SupportedOSPlatform("windows")]
    public void DefaultAcl_AllowsCurrentUserAndLocalSystem()
    {
        var rules = AllowRules(IpcPipeSecurity.Build(IpcOptions.Default));
        var currentUser = WindowsIdentity.GetCurrent().User;
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

        Assert.Contains(rules, r => r.IdentityReference.Equals(localSystem));
        if (currentUser is not null)
            Assert.Contains(rules, r => r.IdentityReference.Equals(currentUser));
    }

    [WindowsOnlyFact]
    [SupportedOSPlatform("windows")]
    public void ConfiguredPrincipal_IsGrantedReadWrite()
    {
        // Built-in Users group, a stable well-known SID present on every machine.
        const string usersGroupSid = "S-1-5-32-545";
        var options = new IpcOptions { AllowedPrincipalSids = new[] { usersGroupSid } };

        var rules = AllowRules(IpcPipeSecurity.Build(options));
        var users = new SecurityIdentifier(usersGroupSid);

        var grant = rules.FirstOrDefault(r => r.IdentityReference.Equals(users));
        Assert.NotNull(grant);
        // Configured principals are clients (read/write), never full control.
        Assert.True((grant!.PipeAccessRights & PipeAccessRights.ReadWrite) == PipeAccessRights.ReadWrite);
        Assert.False(grant.PipeAccessRights.HasFlag(PipeAccessRights.FullControl));
    }

    [WindowsOnlyFact]
    [SupportedOSPlatform("windows")]
    public void InvalidConfiguredPrincipal_IsIgnored_DoesNotBroadenAccess()
    {
        var baseline = AllowRules(IpcPipeSecurity.Build(IpcOptions.Default)).Count;

        var options = new IpcOptions
        {
            AllowedPrincipalSids = new[] { "not-a-sid", "", "   ", "S-1-???" },
        };
        var rules = AllowRules(IpcPipeSecurity.Build(options));

        // No grants were added for the garbage entries, and Everyone is still absent.
        Assert.Equal(baseline, rules.Count);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        Assert.DoesNotContain(rules, r => r.IdentityReference.Equals(everyone));
    }

    [WindowsOnlyTheory]
    [InlineData("S-1-1-0")]      // Everyone
    [InlineData("S-1-5-7")]      // Anonymous
    [InlineData("S-1-5-2")]      // Network
    [InlineData("S-1-5-32-546")] // Guests
    [SupportedOSPlatform("windows")]
    public void ConfiguredForbiddenPrincipal_IsNotGranted(string forbiddenSid)
    {
        var options = new IpcOptions { AllowedPrincipalSids = new[] { forbiddenSid } };
        var rules = AllowRules(IpcPipeSecurity.Build(options));
        var sid = new SecurityIdentifier(forbiddenSid);

        Assert.DoesNotContain(rules, r => r.IdentityReference.Equals(sid));
        // No allow grant was added at all for the forbidden entry.
        Assert.Equal(AllowRules(IpcPipeSecurity.Build(IpcOptions.Default)).Count, rules.Count);
    }

    [WindowsOnlyFact]
    [SupportedOSPlatform("windows")]
    public void MixedList_GrantsOnlyTheValidPrincipal()
    {
        const string usersGroupSid = "S-1-5-32-545"; // valid, allowed
        var options = new IpcOptions
        {
            AllowedPrincipalSids = new[]
            {
                "S-1-1-0",       // Everyone   (forbidden)
                "S-1-5-7",       // Anonymous  (forbidden)
                "S-1-5-2",       // Network    (forbidden)
                "S-1-5-32-546",  // Guests     (forbidden)
                "not-a-sid",     // invalid
                usersGroupSid,   // valid
            },
        };

        var rules = AllowRules(IpcPipeSecurity.Build(options));
        var baseline = AllowRules(IpcPipeSecurity.Build(IpcOptions.Default)).Count;

        // Exactly one extra allow rule beyond the default set — the valid one.
        Assert.Equal(baseline + 1, rules.Count);
        Assert.Contains(rules, r => r.IdentityReference.Equals(new SecurityIdentifier(usersGroupSid)));

        foreach (var forbidden in new[] { "S-1-1-0", "S-1-5-7", "S-1-5-2", "S-1-5-32-546" })
            Assert.DoesNotContain(rules, r => r.IdentityReference.Equals(new SecurityIdentifier(forbidden)));
    }

    [WindowsOnlyFact]
    [SupportedOSPlatform("windows")]
    public void IsForbiddenPrincipal_FlagsBroadPrincipals_AndAllowsUsersGroup()
    {
        Assert.True(IpcPipeSecurity.IsForbiddenPrincipal(new SecurityIdentifier("S-1-1-0")));      // Everyone
        Assert.True(IpcPipeSecurity.IsForbiddenPrincipal(new SecurityIdentifier("S-1-5-7")));      // Anonymous
        Assert.True(IpcPipeSecurity.IsForbiddenPrincipal(new SecurityIdentifier("S-1-5-2")));      // Network
        Assert.True(IpcPipeSecurity.IsForbiddenPrincipal(new SecurityIdentifier("S-1-5-32-546"))); // Guests

        // The built-in Users group is a legitimate configurable principal.
        Assert.False(IpcPipeSecurity.IsForbiddenPrincipal(new SecurityIdentifier("S-1-5-32-545")));
        // Local System (a default grant) is not "forbidden" as a configured principal.
        Assert.False(IpcPipeSecurity.IsForbiddenPrincipal(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)));
    }

    [WindowsOnlyFact]
    [SupportedOSPlatform("windows")]
    public void TryResolveSid_RejectsGarbage_AndAcceptsWellKnownSid()
    {
        Assert.False(IpcPipeSecurity.TryResolveSid("not-a-sid", out _));
        Assert.False(IpcPipeSecurity.TryResolveSid(null, out _));
        Assert.False(IpcPipeSecurity.TryResolveSid("   ", out _));

        Assert.True(IpcPipeSecurity.TryResolveSid("S-1-5-18", out var system));
        Assert.NotNull(system);
        Assert.Equal(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), system);
    }

    // ── Host construction + authorized round-trip over the ACL'd pipe ────────

    [Fact]
    public async Task Host_ConstructsAclPipe_AndHonorsCancellation()
    {
        // Exercises CreateServerStream() (the ACL path on Windows). A pre-cancelled
        // token makes the wait return false without ever crashing on the security
        // descriptor — proving the hardened pipe constructs cleanly.
        var options = new IpcOptions { PipeName = "DataVanger.Test.Acl." + Guid.NewGuid().ToString("N") };
        var host = new NamedPipeDataVangerServiceHost(new PongHost(), options);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        bool served = await host.ProcessNextAsync(cts.Token);
        Assert.False(served);
    }

    [Fact]
    public async Task AuthorizedClient_RoundTrip_StillSucceeds_OverHardenedPipe()
    {
        // The running test principal is, by construction, an allowed principal
        // (it creates the pipe). This proves ACL hardening does NOT block the
        // legitimate local client.
        var options = new IpcOptions { PipeName = "DataVanger.Test.Acl." + Guid.NewGuid().ToString("N") };
        var host = new NamedPipeDataVangerServiceHost(new PongHost(), options);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serveTask = host.ProcessNextAsync(cts.Token);

        var client = new NamedPipeDataVangerServiceClient(options);
        DataVangerResponse response = await client.SendAsync(
            DataVangerRequest.Create(DataVangerCommandType.Ping), cts.Token);

        Assert.True(response.Success);
        Assert.Equal(IpcStatusCode.Ok, response.StatusCode);
        Assert.Equal("pong", response.Message);

        bool served = await serveTask;
        Assert.True(served);
    }

    // ── Payload validation is preserved (IpcSecurityPolicy unchanged) ────────

    [Fact]
    public void Policy_StillRejects_UnknownCommand()
    {
        var request = DataVangerRequest.Create(DataVangerCommandType.Unknown);
        var result = IpcSecurityPolicy.ValidateRequest(request, IpcOptions.Default);
        Assert.False(result.IsValid);
        Assert.Equal(IpcStatusCode.UnknownCommand, result.StatusCode);
    }

    [Fact]
    public void Policy_StillRejects_OversizePayload()
    {
        var options = new IpcOptions { MaxMessageBytes = 256 };
        var request = new DataVangerRequest
        {
            CommandType = DataVangerCommandType.StartCustomScan,
            PayloadJson = new string('x', options.MaxMessageBytes + 1),
        };
        var result = IpcSecurityPolicy.ValidateRequest(request, options);
        Assert.False(result.IsValid);
        Assert.Equal(IpcStatusCode.PayloadTooLarge, result.StatusCode);
    }

    [Fact]
    public void Policy_StillRejects_UnsafePaths()
    {
        Assert.False(IpcSecurityPolicy.IsSafePath(@"..\..\Windows\System32"));
        Assert.False(IpcSecurityPolicy.IsSafePath(@"\\remote\share\file"));
        Assert.True(IpcSecurityPolicy.TryValidateScanPaths(Array.Empty<string>(), out _) == false);
    }

    [Fact]
    public void Policy_StillAccepts_AllowedCommand()
    {
        var request = DataVangerRequest.Create(DataVangerCommandType.GetServiceStatus);
        var result = IpcSecurityPolicy.ValidateRequest(request, IpcOptions.Default);
        Assert.True(result.IsValid);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    [SupportedOSPlatform("windows")]
    private static List<PipeAccessRule> AllowRules(PipeSecurity security)
        => security
            .GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>()
            .Where(r => r.AccessControlType == AccessControlType.Allow)
            .ToList();

    /// <summary>Minimal inner host that answers Ping with "pong".</summary>
    private sealed class PongHost : IDataVangerServiceHost
    {
        public Task<DataVangerResponse> HandleAsync(DataVangerRequest request, CancellationToken cancellationToken = default)
            => Task.FromResult(DataVangerResponse.Ok(request.RequestId, message: "pong"));
    }
}
