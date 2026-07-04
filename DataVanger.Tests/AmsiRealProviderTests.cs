using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Core;
using DataVanger.Infrastructure.Ipc;
using DataVanger.Runtime;
using DataVanger.Runtime.Amsi;
using DataVanger.Service.Hosting;
using DataVanger.Service.Runtime;
using DataVanger.Shared.RuntimeEvents;
using DataVanger.Shared.Service;
using Xunit;

namespace DataVanger.Tests;

// Real AMSI provider (IAntimalwareProvider via native shim + IPC), managed side.
//
// These tests pin the security-critical guarantees of the design:
//   - the ingest decoder treats every frame as hostile and fails OPEN (a
//     malformed/oversized/partial frame yields no event and never throws);
//   - an AMSI-origin observation is evidence-only and NEVER reaches a
//     quarantine/block decision;
//   - exactly one AMSI provider is hosted, so the real and in-memory paths
//     never run in parallel and events are never duplicated;
//   - the COM registration plan is admin-gated and structurally correct without
//     executing anything;
//   - the ingest pipe ACL grants Authenticated Users connect+write ONLY.
//
// The native shim itself is validated manually on Windows (see docs/AMSI_PROVIDER.md).
// Filter: ~Amsi.
public class AmsiRealProviderTests
{
    private const string BypassPayload =
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')" +
        ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)";

    // ── Protocol: strict round-trip + fail-open decode ───────────────────────

    [Fact]
    public void Protocol_RoundTrips_AllFields()
    {
        var frame = AmsiIngestProtocol.Encode("PowerShell", "prompt.ps1", pid: 4242, session: 7, content: BypassPayload);

        Assert.True(AmsiIngestProtocol.TryDecode(frame, out var message));
        Assert.Equal("PowerShell", message.AppName);
        Assert.Equal("prompt.ps1", message.ContentName);
        Assert.Equal(4242, message.Pid);
        Assert.Equal(7UL, message.Session);
        Assert.Equal(BypassPayload, message.Content);
    }

    [Fact]
    public void Protocol_Rejects_WrongMagic()
    {
        var frame = AmsiIngestProtocol.Encode("ps", "", 1, 0, "x");
        frame[0] = (byte)'X'; // corrupt the magic

        Assert.False(AmsiIngestProtocol.TryDecode(frame, out _));
    }

    [Fact]
    public void Protocol_Rejects_TruncatedFrame()
    {
        var frame = AmsiIngestProtocol.Encode("ps", "", 1, 0, "some content");
        var truncated = frame.AsSpan(0, frame.Length - 3).ToArray(); // drop trailing content bytes

        Assert.False(AmsiIngestProtocol.TryDecode(truncated, out _));
    }

    [Fact]
    public void Protocol_Rejects_HeaderOnly_AndEmpty()
    {
        Assert.False(AmsiIngestProtocol.TryDecode(ReadOnlySpan<byte>.Empty, out _));
        Assert.False(AmsiIngestProtocol.TryDecode(new byte[AmsiIngestProtocol.HeaderBytes - 1], out _));
    }

    [Fact]
    public void Protocol_Rejects_OverCapContentLengthField()
    {
        // A well-formed header that lies about contentLen (> MaxContentBytes)
        // must be rejected before any allocation keyed on that length.
        var frame = AmsiIngestProtocol.Encode("ps", "", 1, 0, "x");
        // contentLen is the u32 at offset 20.
        frame[20] = 0xFF; frame[21] = 0xFF; frame[22] = 0xFF; frame[23] = 0x7F;

        Assert.False(AmsiIngestProtocol.TryDecode(frame, out _));
    }

    [Fact]
    public void Protocol_Encode_TruncatesOverlongContent_ToACap()
    {
        var huge = new string('A', AmsiIngestProtocol.MaxContentBytes + 5000);
        var frame = AmsiIngestProtocol.Encode("ps", "", 1, 0, huge);

        Assert.True(frame.Length <= AmsiIngestProtocol.MaxFrameBytes);
        Assert.True(AmsiIngestProtocol.TryDecode(frame, out var message));
        Assert.True(message.Content.Length <= AmsiIngestProtocol.MaxContentBytes);
    }

    // ── Provider: fail-open ingest (req #6a) ─────────────────────────────────

    [Fact]
    public void IngestFrame_MalformedOrPartial_RaisesNoEvent_AndNeverThrows()
    {
        using var provider = new PipeIngestAmsiProvider();
        provider.Start();
        int events = 0;
        provider.EventReceived += _ => Interlocked.Increment(ref events);

        // Random noise, truncated frame, empty — none may throw or emit.
        Assert.Equal(0, provider.IngestFrame(new byte[] { 1, 2, 3, 4, 5 }));
        Assert.Equal(0, provider.IngestFrame(ReadOnlySpan<byte>.Empty));

        var valid = AmsiIngestProtocol.Encode("ps", "", 1, 0, "x");
        Assert.Equal(0, provider.IngestFrame(valid.AsSpan(0, valid.Length - 2)));

        Assert.Equal(0, events);
        Assert.True(provider.RejectedFrames >= 3);
    }

    [Fact]
    public void IngestFrame_OversizedFrame_IsRejected_NoThrow()
    {
        using var provider = new PipeIngestAmsiProvider();
        provider.Start();

        var oversized = new byte[AmsiIngestProtocol.MaxFrameBytes + 100];
        Assert.Equal(0, provider.IngestFrame(oversized));
    }

    [Fact]
    public void IngestFrame_BenignContent_ProducesNoEvent()
    {
        using var provider = new PipeIngestAmsiProvider();
        provider.Start();
        int events = 0;
        provider.EventReceived += _ => Interlocked.Increment(ref events);

        var frame = AmsiIngestProtocol.Encode("PowerShell", "", 10, 0, "Get-ChildItem C:\\ | Select-Object Name");
        Assert.Equal(0, provider.IngestFrame(frame));
        Assert.Equal(0, events);
    }

    [Fact]
    public void IngestFrame_SuspiciousContent_RaisesObservationalEvent()
    {
        using var provider = new PipeIngestAmsiProvider();
        provider.Start();
        var received = new List<RuntimeTelemetryEvent>();
        provider.EventReceived += e => { lock (received) received.Add(e); };

        var frame = AmsiIngestProtocol.Encode("PowerShell", "", 20, 0, BypassPayload);
        int published = provider.IngestFrame(frame);

        Assert.True(published >= 1);
        Assert.NotEmpty(received);
        Assert.All(received, e => Assert.Equal("pipe-ingest-amsi", e.ProviderName));
    }

    [Fact]
    public void IngestFrame_PastRateCeiling_ThrottlesWithoutThrowing()
    {
        using var provider = new PipeIngestAmsiProvider(new PipeIngestOptions
        {
            MaxMessagesPerWindow = 3,
            RateWindow = TimeSpan.FromSeconds(30),
        });
        provider.Start();

        var frame = AmsiIngestProtocol.Encode("PowerShell", "", 20, 0, BypassPayload);
        for (int i = 0; i < 20; i++) provider.IngestFrame(frame);

        Assert.True(provider.ThrottledFrames > 0, "Frames past the window ceiling must be throttled.");
        Assert.True(provider.IngestedFrames >= 20);
    }

    [Fact]
    public void Provider_Lifecycle_IsIdempotentAndSafe()
    {
        var provider = new PipeIngestAmsiProvider();
        provider.Start();
        provider.Start();  // idempotent
        provider.Stop();
        provider.Stop();   // safe
        provider.Dispose();
        provider.Dispose(); // safe

        // After disposal, ingest is inert (no throw, no event).
        Assert.Equal(0, provider.IngestFrame(AmsiIngestProtocol.Encode("ps", "", 1, 0, BypassPayload)));
    }

    // ── Anti-block: AMSI observation never becomes a verdict/action (req #6b) ─

    [Fact]
    public void AmsiIngest_Observation_IsScriptObservedOnly_NeverARemediationCategory()
    {
        using var provider = new PipeIngestAmsiProvider();
        var publisher = new CapturingPublisher();
        using var bridge = new AmsiRuntimeBridge(provider, publisher);
        provider.Start();

        provider.IngestFrame(AmsiIngestProtocol.Encode("PowerShell", "", 20, 0, BypassPayload));

        Assert.NotEmpty(publisher.Events);
        Assert.All(publisher.Events, e =>
        {
            // The bridge is the ONLY sink for AMSI telemetry, and it only ever
            // produces observational ScriptObserved events — there is no code
            // path from here to quarantine/block.
            Assert.Equal(RuntimeEventCategory.ScriptObserved, e.Category);
            Assert.Equal(RuntimeEventSource.AmsiContentAnalysis, e.Source);
            // The submitted script body is never retained in metadata.
            Assert.False(e.Metadata.ContainsKey("amsi.script"));
        });
    }

    [Fact]
    public void AmsiDerivedFinding_IsNeverConfirmedMalware_AndNeverAutoActioned()
    {
        // A finding whose only signal is an AMSI/runtime observation (no known-bad
        // hash, no confirmed signature) must never classify as ConfirmedMalware and
        // must never authorize an automatic quarantine/block action.
        var finding = new ScanFinding
        {
            Path = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            Score = RiskThresholds.Suspect,
            Evidence = new List<Evidence>
            {
                new() { Category = "Runtime", Description = "amsi ingest observation",
                        ScoreDelta = 6, Strength = EvidenceStrength.Medium, CanConfirmMalware = false },
            },
            IsBlacklisted = false,
            HasConfirmedSignature = false,
        };

        Assert.NotEqual(ThreatClass.ConfirmedMalware, ThreatClassificationPolicy.Classify(finding));
        Assert.False(ThreatClassificationPolicy.AllowsAutomaticAction(finding));
    }

    // ── Coexistence: a single provider is hosted, never duplicated (req #6c) ──

    [Fact]
    public async Task Runtime_WithRealAmsiEnabled_HostsExactlyOneProvider()
    {
        int created = 0;
        using var runtime = new DataVangerServiceRuntime(
            new DataVangerServiceConfiguration { EnableRealAmsiProvider = true },
            DataVangerRuntimeMode.Service,
            amsiProviderFactory: () => { Interlocked.Increment(ref created); return new InMemoryAmsiProvider(); });

        await runtime.StartAsync(CancellationToken.None);
        await runtime.StartAsync(CancellationToken.None); // idempotent — must not create a second provider

        Assert.Equal(1, created);
        Assert.False(runtime.GetStatusSnapshot().HasActiveProtection);

        await runtime.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Runtime_RealAmsiEnabled_OnWindows_SelectsIngestProvider_StillPassive()
    {
        if (!OperatingSystem.IsWindows()) return;

        using var runtime = new DataVangerServiceRuntime(
            new DataVangerServiceConfiguration { EnableRealAmsiProvider = true },
            DataVangerRuntimeMode.Service);

        await runtime.StartAsync(CancellationToken.None);

        var snap = runtime.GetStatusSnapshot();
        var amsi = Assert.Single(snap.Modules, m => m.Name == "AmsiRuntime");
        Assert.Contains("Real AMSI provider ingest", amsi.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.False(amsi.IsActiveProtection);
        Assert.False(snap.HasActiveProtection);

        await runtime.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Runtime_RealAmsiDisabled_UsesInMemoryProvider()
    {
        using var runtime = new DataVangerServiceRuntime(
            DataVangerServiceConfiguration.SafeDefaults(), DataVangerRuntimeMode.Service);

        await runtime.StartAsync(CancellationToken.None);

        var amsi = Assert.Single(runtime.GetStatusSnapshot().Modules, m => m.Name == "AmsiRuntime");
        Assert.Contains("In-memory AMSI", amsi.Detail, StringComparison.OrdinalIgnoreCase);

        await runtime.StopAsync(CancellationToken.None);
    }

    // ── Registration: admin-gated + structurally correct plan (no execution) ──

    [Fact]
    public void RegisterPlan_UsesRegExe_AndWiresClsidInprocServerAndAmsiKey()
    {
        var plan = AmsiProviderRegistration.BuildRegisterPlan(
            AmsiProviderRegistration.ProviderClsid, @"C:\dv\DataVanger.AmsiProvider.dll");

        Assert.All(plan, c => Assert.Equal("reg.exe", c.FileName));

        // The CLSID's InprocServer32 default value must be the provider DLL path.
        Assert.Contains(plan, c =>
            c.Arguments.Any(a => a.Contains(@"\InprocServer32", StringComparison.OrdinalIgnoreCase))
            && c.Arguments.Contains(@"C:\dv\DataVanger.AmsiProvider.dll"));

        // ThreadingModel=Both is set on the InprocServer32 key.
        Assert.Contains(plan, c => c.Arguments.Contains("ThreadingModel") && c.Arguments.Contains("Both"));

        // The CLSID is listed under the AMSI Providers key.
        Assert.Contains(plan, c =>
            c.Arguments.Any(a => a.Contains(@"AMSI\Providers", StringComparison.OrdinalIgnoreCase)
                                 && a.Contains(AmsiProviderRegistration.ProviderClsid, StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public void UnregisterPlan_RemovesAmsiKeyThenClsid()
    {
        var plan = AmsiProviderRegistration.BuildUnregisterPlan(AmsiProviderRegistration.ProviderClsid);

        Assert.Equal(2, plan.Count);
        Assert.All(plan, c => Assert.Equal("delete", c.Arguments[0]));
        Assert.Contains(@"AMSI\Providers", plan[0].Arguments[1]);
        Assert.Contains(@"\CLSID\", plan[1].Arguments[1]);
    }

    [Fact]
    public void ProviderDllPath_MustBeAbsoluteAndExist()
    {
        Assert.False(AmsiProviderRegistration.TryValidateProviderDllPath("relative\\path.dll", out _));
        Assert.False(AmsiProviderRegistration.TryValidateProviderDllPath(
            Path.Combine(Path.GetTempPath(), "does-not-exist-" + Guid.NewGuid().ToString("N") + ".dll"), out _));

        var existing = Path.Combine(Path.GetTempPath(), "dv-amsi-" + Guid.NewGuid().ToString("N") + ".dll");
        File.WriteAllText(existing, "stub");
        try
        {
            Assert.True(AmsiProviderRegistration.TryValidateProviderDllPath(existing, out var reason));
            Assert.Equal("", reason);
        }
        finally { File.Delete(existing); }
    }

    [Fact]
    public void Register_OnNonWindows_ReportsUnsupported_NoCrash()
    {
        if (OperatingSystem.IsWindows()) return;

        var output = new StringWriter();
        var error = new StringWriter();
        int code = AmsiProviderRegistration.Register(output, error);

        Assert.Equal(AmsiProviderRegistration.ExitUnsupportedPlatform, code);
        Assert.Contains("only on Windows", error.ToString());
    }

    [Fact]
    public void Unregister_OnNonWindows_ReportsUnsupported_NoCrash()
    {
        if (OperatingSystem.IsWindows()) return;

        var output = new StringWriter();
        var error = new StringWriter();
        int code = AmsiProviderRegistration.Unregister(output, error);

        Assert.Equal(AmsiProviderRegistration.ExitUnsupportedPlatform, code);
        Assert.Contains("only on Windows", error.ToString());
    }

    // ── Ingest ACL: Authenticated Users connect+write ONLY (Windows only) ────

    [Fact]
    public void IngestAcl_GrantsAuthenticatedUsers_WriteOnly_NeverReadOrCreateInstance()
    {
        if (!OperatingSystem.IsWindows()) return;

        var security = IpcPipeSecurity.BuildIngestAcl();
        var rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>()
            .ToList();

        var authUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
        var allow = rules.Single(r =>
            r.IdentityReference.Equals(authUsers) && r.AccessControlType == AccessControlType.Allow);

        Assert.True((allow.PipeAccessRights & PipeAccessRights.WriteData) != 0, "must allow write");
        Assert.True((allow.PipeAccessRights & PipeAccessRights.ReadData) == 0, "must NOT allow read");
        Assert.True((allow.PipeAccessRights & PipeAccessRights.CreateNewInstance) == 0, "must NOT allow instance creation");

        // Network logons are denied.
        var network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);
        Assert.Contains(rules, r =>
            r.IdentityReference.Equals(network) && r.AccessControlType == AccessControlType.Deny);
    }

    // ── End-to-end listener (Windows only): a real client frame reaches a subscriber ─

    [Fact]
    public async Task IngestListener_OnWindows_DeliversAConnectedClientFrame()
    {
        if (!OperatingSystem.IsWindows()) return;

        var pipeName = "DataVanger.Test.AmsiIngest." + Guid.NewGuid().ToString("N");
        using var provider = new PipeIngestAmsiProvider(new PipeIngestOptions { PipeName = pipeName });
        var received = new List<RuntimeTelemetryEvent>();
        provider.EventReceived += e => { lock (received) received.Add(e); };

        Assert.Equal(RuntimeProviderState.Running, provider.Start());

        using (var client = new NamedPipeClientStream(".", pipeName, PipeDirection.Out))
        {
            await client.ConnectAsync(2000);
            var frame = AmsiIngestProtocol.Encode("PowerShell", "", 4242, 0, BypassPayload);
            await client.WriteAsync(frame);
            await client.FlushAsync();
        }

        // The listener processes on a background thread; poll briefly.
        var deadline = DateTime.UtcNow.AddSeconds(3);
        while (DateTime.UtcNow < deadline)
        {
            lock (received) { if (received.Count > 0) break; }
            await Task.Delay(25);
        }

        lock (received) Assert.NotEmpty(received);
        provider.Stop();
    }

    private sealed class CapturingPublisher : IRuntimeEventPublisher
    {
        public List<RuntimeSecurityEvent> Events { get; } = new();

        public ValueTask PublishAsync(RuntimeSecurityEvent runtimeEvent, CancellationToken cancellationToken = default)
        {
            if (runtimeEvent is not null)
            {
                lock (Events) Events.Add(runtimeEvent);
            }
            return ValueTask.CompletedTask;
        }
    }
}
