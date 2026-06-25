using Xunit;

// Phase 09 decomposition — Service IPC and UI Integration (Phase 2 / Step 11).
// Faithful move: runs the unchanged internal Phase11ServiceIpcUi.Run(...) helper as its own
// independently runnable, filterable [Fact]. Identical assertions/messages via the shared
// LegacyAssert shim. Filter: --filter "FullyQualifiedName~Ipc" (also matches ~Service).
public class ServiceIpcTests
{
    [Fact]
    public void ServiceIpcAndUi_AllLegacyChecks() => Phase11ServiceIpcUi.Run(LegacyAssert.True);
}
