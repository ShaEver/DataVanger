using System;
using System.Linq;
using DataVanger.Engine.Updates.SignedUpdates;
using DataVanger.Memory;
using DataVanger.Service.Runtime;
using DataVanger.Shared.Service;
using DataVanger.Shared.Status;
using Xunit;

// Pins the load-bearing "code-reality" status claims to VERIFIABLE CODE FACTS.
//
// Root cause this guards against: CodeRealityModuleMatrix lives in DataVanger.Shared (the
// base layer), which references nothing and therefore cannot observe the code it describes —
// so every claim is a hand-typed string with nothing forcing it to match reality. That is
// exactly how the http-update-transport entry kept claiming "throws NotSupportedException"
// long after the transport was implemented and wired. These tests assert the matrix state
// against real runtime behaviour, so a stale/false claim breaks the build instead of shipping.
public class ModuleStatusClaimTests
{
    private static ModuleStatus Find(string key) =>
        CodeRealityModuleMatrix.Create().Single(m => m.Key == key);

    // CODE FACT: HttpUpdateTransport is a real, opt-in transport that NEVER throws
    // NotSupportedException — it just returns null when disabled. If it is ever reverted to a
    // throwing stub, this fails.
    [Fact]
    public void HttpUpdateTransport_IsRealNonThrowingOptInTransport()
    {
        using var transport = new HttpUpdateTransport(HttpUpdateTransportOptions.Disabled);

        byte[]? manifest = null;
        var ex = Record.Exception(() => { manifest = transport.GetManifestBytes(); });

        Assert.Null(ex);       // does NOT throw (the matrix once falsely claimed it did)
        Assert.Null(manifest); // inert when disabled: returns null, not an exception
    }

    // Bind the matrix claim to that code fact: since the transport is real (not a throwing
    // stub), the matrix must not label it Stub, and its Detail must not repeat the old lie.
    [Fact]
    public void Matrix_HttpUpdateTransport_NotStub_AndNoStaleThrowClaim()
    {
        var t = Find("http-update-transport");
        Assert.NotEqual(ModuleOperatingState.Stub, t.State);
        Assert.DoesNotContain("NotSupportedException", t.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("throws", t.Detail, StringComparison.OrdinalIgnoreCase);
    }

    // CODE FACT: the real-libyara matrix state must match the actual YARA_REAL compile symbol,
    // surfaced by LibyaraEngine.RealBackendCompiledIn (the Shared matrix cannot see the symbol
    // itself). Dropping the symbol without updating the matrix then breaks the build.
    [Fact]
    public void Matrix_RealLibyara_MatchesCompileProbe()
    {
        var expected = DataVanger.Infrastructure.LibyaraEngine.RealBackendCompiledIn
            ? ModuleOperatingState.Active
            : ModuleOperatingState.Fallback;
        Assert.Equal(expected, Find("real-libyara").State);
    }

    [Fact]
    public void Matrix_DefaultNullMemoryReader_IsUnavailable_NotActive()
    {
        var scanner = MemoryScannerFactory.CreateSafeDefault();
        Assert.False(scanner.IsSupported);
        Assert.Equal(ModuleOperatingState.Unavailable, Find("memory-scanner").State);
        Assert.False(Find("memory-scanner").IsActiveProtection);
    }

    [Fact]
    public async Task Matrix_DefaultServiceAndObserveOnlyProviders_NeverClaimActiveProtection()
    {
        using var runtime = new DataVangerServiceRuntime(
            DataVangerServiceConfiguration.SafeDefaults(),
            DataVangerRuntimeMode.Development);
        await runtime.StartAsync(CancellationToken.None);

        Assert.False(runtime.GetStatusSnapshot().HasActiveProtection);
        Assert.Equal(ModuleOperatingState.Passive, Find("amsi-runtime").State);
        Assert.False(Find("amsi-runtime").IsActiveProtection);
        Assert.Equal(ModuleOperatingState.Prepared, Find("named-pipe-ipc").State);
    }
}
