using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Infrastructure.Ipc;
using DataVanger.Service.Ipc;
using DataVanger.Shared.Ipc;
using Xunit;

// Phase 02B — IPC ACL security gate tests. Runnable via:
//   dotnet test --filter "FullyQualifiedName~IpcAclGate"
// Contract under test: the host can be put into a REQUIRED-hardening mode that
// fails closed (throws) rather than ever opening an unrestricted pipe; the
// command catalog is the first authority and rejects out-of-range commands
// before any handler; existing bounds remain authoritative and unweakened.
public class IpcAclGateTests
{
    private sealed class NeverCalledHost : IDataVangerServiceHost
    {
        public Task<DataVangerResponse> HandleAsync(DataVangerRequest request, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("Handler must not be reached.");
    }

    // ── Fail-closed REQUIRED hardening (cross-platform deterministic) ────────

    [Fact]
    public async Task RequireAclHardening_WithHardeningDisabled_RefusesToOpenPlainPipe()
    {
        var options = new IpcOptions
        {
            PipeName = "DataVanger.Test.Gate." + Guid.NewGuid().ToString("N"),
            HardenPipeAcl = false,
            RequireAclHardening = true,
        };
        var host = new NamedPipeDataVangerServiceHost(new NeverCalledHost(), options);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => host.ProcessNextAsync(CancellationToken.None));

        Assert.Contains("Refusing to open an unrestricted pipe", ex.Message);
    }

    [Fact]
    public async Task RequireAclHardening_OnNonWindows_FailsClosed_NeverPlainPipe()
    {
        // On Windows the hardened path is available, so this scenario cannot
        // occur there — the non-Windows half is the meaningful one.
        if (OperatingSystem.IsWindows()) return;

        var options = new IpcOptions
        {
            PipeName = "DataVanger.Test.Gate." + Guid.NewGuid().ToString("N"),
            HardenPipeAcl = true,            // requested...
            RequireAclHardening = true,      // ...and REQUIRED
        };
        var host = new NamedPipeDataVangerServiceHost(new NeverCalledHost(), options);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => host.ProcessNextAsync(CancellationToken.None));

        Assert.Contains("does not support pipe security descriptors", ex.Message);
    }

    [Fact]
    public void RequireAclHardening_DefaultsToFalse_SoTestTransportsKeepWorking()
    {
        Assert.False(IpcOptions.Default.RequireAclHardening);
        Assert.True(IpcOptions.Default.HardenPipeAcl);
    }

    [WindowsOnlyFact]
    [SupportedOSPlatform("windows")]
    public async Task RequireAclHardening_WhenAclConstructionFails_DoesNotFallbackToPlainPipe()
    {
        var options = new IpcOptions
        {
            PipeName = "DataVanger.Test.Gate." + Guid.NewGuid().ToString("N"),
            HardenPipeAcl = true,
            RequireAclHardening = true,
            AllowedPrincipalSids = new ThrowingPrincipalList(),
        };
        var host = new NamedPipeDataVangerServiceHost(new NeverCalledHost(), options);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => host.ProcessNextAsync(CancellationToken.None));

        Assert.Contains("Simulated ACL principal enumeration failure", ex.Message);
    }

    // ── Catalog is the first authority (before any handler dispatch) ─────────

    [Fact]
    public void OutOfRangeCommandEnum_IsRejectedByPolicy_BeforeAnyHandler()
    {
        var request = new DataVangerRequest
        {
            RequestId = Guid.NewGuid().ToString("N"),
            CommandType = (DataVangerCommandType)9999, // fuzzed/unknown id
        };

        var result = IpcSecurityPolicy.ValidateRequest(request, IpcOptions.Default);

        Assert.False(result.IsValid);
        Assert.Equal(IpcStatusCode.UnknownCommand, result.StatusCode);
    }

    [Fact]
    public async Task OutOfRangeCommandEnum_IsRejectedByRouter_BeforeCategoryDispatch()
    {
        var router = new DataVangerServiceCommandRouter(new DataVangerServiceCommandContext());
        var request = new DataVangerRequest
        {
            RequestId = Guid.NewGuid().ToString("N"),
            CommandType = (DataVangerCommandType)9999,
        };

        DataVangerResponse response = await router.HandleAsync(request, CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal(IpcStatusCode.UnknownCommand, response.StatusCode);
        Assert.Equal("UnknownCommand", response.ErrorCode);
        Assert.Contains("not on the allowlist", response.Message);
    }

    // ── Bounds remain authoritative and unweakened ───────────────────────────

    [Fact]
    public void SizeBounds_AreUnchanged_AndCannotBeDisabled()
    {
        // Phase invariant: 64 KiB default, 1 MiB hard ceiling. A configured
        // value above the ceiling clamps down; a degenerate value falls back
        // to the default. Tightening is allowed; weakening is not.
        Assert.Equal(64 * 1024, IpcOptions.DefaultMaxMessageBytes);
        Assert.Equal(1024 * 1024, IpcOptions.AbsoluteMaxMessageBytes);

        Assert.Equal(IpcOptions.AbsoluteMaxMessageBytes,
            new IpcOptions { MaxMessageBytes = int.MaxValue }.MaxMessageBytes);
        Assert.Equal(IpcOptions.DefaultMaxMessageBytes,
            new IpcOptions { MaxMessageBytes = 0 }.MaxMessageBytes);
    }

    [Fact]
    public async Task OversizedFrame_IsRejected_BeforeBusinessHandling_NoCrash()
    {
        // End-to-end over the public surface: a client declares a frame far
        // above the bound. The host must reject it (framing throws inside,
        // host drops the connection), never crash, and never dispatch to the
        // inner handler — NeverCalledHost would throw InvalidOperationException,
        // which the host deliberately does NOT swallow, so reaching the handler
        // would fail this test.
        var options = new IpcOptions
        {
            PipeName = "DataVanger.Test.Gate." + Guid.NewGuid().ToString("N"),
            MaxMessageBytes = 1024,
        };
        var host = new NamedPipeDataVangerServiceHost(new NeverCalledHost(), options);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serveTask = host.ProcessNextAsync(cts.Token);

        using (var client = new System.IO.Pipes.NamedPipeClientStream(
            ".", options.PipeName, System.IO.Pipes.PipeDirection.InOut,
            System.IO.Pipes.PipeOptions.Asynchronous))
        {
            await client.ConnectAsync(cts.Token);
            byte[] poisonedHeader = BitConverter.GetBytes(int.MaxValue);
            await client.WriteAsync(poisonedHeader, cts.Token);
            await client.FlushAsync(cts.Token);
        }

        bool served = await serveTask;
        Assert.True(served); // connection was handled (rejected) without crash
    }

    private sealed class ThrowingPrincipalList : IReadOnlyList<string>
    {
        public int Count => 1;

        public string this[int index] =>
            throw new InvalidOperationException("Simulated ACL principal access failure.");

        public IEnumerator<string> GetEnumerator() =>
            throw new InvalidOperationException("Simulated ACL principal enumeration failure.");

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
