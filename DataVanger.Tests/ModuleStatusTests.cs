using System;
using System.Linq;
using Xunit;
using DataVanger.Shared.Status;

// Phase 09 decomposition — Module Status and UI Settings (Phase 2 / Step 09).
// Faithful move: runs the unchanged internal Phase09ModuleStatusUiSettings.Run(...) helper
// as its own independently runnable, filterable [Fact]. Identical assertions/messages via
// the shared LegacyAssert shim. Filter: --filter "FullyQualifiedName~ModuleStatus"
// (also matches ~Status).
public class ModuleStatusTests
{
    [Fact]
    public void ModuleStatusAndUiSettings_AllLegacyChecks() => Phase09ModuleStatusUiSettings.Run(LegacyAssert.True);

    // ── Phase 18 — honest code-reality matrix: conservative-state snapshot assertions.
    // These prove prepared/fallback/stub systems are NEVER over-claimed as Active.

    private static ModuleStatus Find(string key) =>
        CodeRealityModuleMatrix.Create().Single(m => m.Key == key);

    [Fact] // tied to the real compile symbol via LibyaraEngine.RealBackendCompiledIn:
           // the Shared matrix cannot see YARA_REAL, so this test enforces consistency —
           // dropping the symbol without updating the matrix breaks the build.
    public void CodeReality_RealLibyara_State_MatchesCompileSymbol()
    {
        var yara = Find("real-libyara");
        var expected = DataVanger.Infrastructure.LibyaraEngine.RealBackendCompiledIn
            ? ModuleOperatingState.Active
            : ModuleOperatingState.Fallback;
        Assert.Equal(expected, yara.State);
        Assert.Contains("fallback", yara.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CodeReality_LightweightYara_IsFallback() =>
        Assert.Equal(ModuleOperatingState.Fallback, Find("yara-lightweight").State);

    [Fact] // was falsely asserted as Stub; HttpUpdateTransport is a real, opt-in transport.
    public void CodeReality_HttpUpdateTransport_IsPrepared_NotStub()
    {
        var t = Find("http-update-transport");
        Assert.Equal(ModuleOperatingState.Prepared, t.State);
        Assert.NotEqual(ModuleOperatingState.Stub, t.State);
    }

    [Fact]
    public void CodeReality_WindowsService_InstallationIsDisabled()
    {
        // The host code remains present, but the P0 gate makes system installation
        // unavailable. The matrix must describe operational reality, not scaffolding.
        var svc = Find("windows-service");
        Assert.Equal(ModuleOperatingState.Disabled, svc.State);
        Assert.Contains("exits 7", svc.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CodeReality_EtwAndAmsi_AreNotActive()
    {
        Assert.NotEqual(ModuleOperatingState.Active, Find("etw-provider").State);
        Assert.NotEqual(ModuleOperatingState.Active, Find("amsi-adapter").State);
    }

    [Fact]
    public void CodeReality_IpcAclHardening_IsActive_AndFailClosedCapable()
    {
        var acl = Find("ipc-acl-hardening");
        Assert.Equal(ModuleOperatingState.Active, acl.State);
        Assert.Contains("fail-closed", acl.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CodeReality_MemoryAndAmsiResidentPaths_ArePrepared_NeverActiveProtection()
    {
        Assert.Equal(ModuleOperatingState.Prepared, Find("memory-runtime").State);
        Assert.Equal(ModuleOperatingState.Prepared, Find("amsi-runtime").State);
        Assert.False(Find("memory-runtime").IsActiveProtection);
        Assert.False(Find("amsi-runtime").IsActiveProtection);
    }

    [Fact]
    public void CodeReality_PublisherTrust_UsesCertificateChainByDefault() =>
        Assert.Contains("certificate chain", Find("trusted-publishers").Detail, StringComparison.OrdinalIgnoreCase);

    [Fact]
    public void CodeReality_NamedPipeIpc_IsActiveLocalOnly() =>
        Assert.Equal(ModuleOperatingState.Active, Find("named-pipe-ipc").State);

    [Fact]
    public void CodeReality_QuarantineV2_IsActive() =>
        Assert.Equal(ModuleOperatingState.Active, Find("quarantine-v2").State);

    [Fact]
    public void CodeReality_SignedUpdateVerification_IsActive_TransportIsImplementedOptIn()
    {
        // Verification is Active; the network transport is implemented but opt-in (Prepared),
        // NOT absent/Stub — the earlier "transport is not [implemented]" framing was wrong.
        Assert.Equal(ModuleOperatingState.Active, Find("signed-update-verification").State);
        Assert.Equal(ModuleOperatingState.Prepared, Find("http-update-transport").State);
    }

    [Fact]
    public void CodeReality_RealtimeProtection_IsNotActive_ResidentRuntimePrepared() =>
        Assert.NotEqual(ModuleOperatingState.Active, Find("realtime-protection").State);

    [Fact]
    public void CodeReality_EveryModule_HasAReason()
    {
        Assert.All(CodeRealityModuleMatrix.Create(),
            m => Assert.False(string.IsNullOrWhiteSpace(m.Detail), $"Module '{m.Key}' must have a reason/detail."));
    }

    [Fact]
    public void CodeReality_KeysAreUnique()
    {
        var keys = CodeRealityModuleMatrix.Create().Select(m => m.Key).ToList();
        Assert.Equal(keys.Count, keys.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void CodeReality_EngineAggregator_ExposesSameMatrix()
    {
        // The Engine pass-through must return the same code-reality matrix the UI consumes.
        var viaEngine = DataVanger.Engine.Status.DefaultModuleStatusCatalog.CreateCodeRealityModules();
        var viaShared = CodeRealityModuleMatrix.Create();
        Assert.Equal(viaShared.Select(m => m.Key), viaEngine.Select(m => m.Key));
    }
}
