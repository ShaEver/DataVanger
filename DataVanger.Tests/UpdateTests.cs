using Xunit;

// Phase 09 decomposition — Signed Updates and Trusted Signature Feed Delivery
// (Phase 2 / Step 10). Faithful move: runs the unchanged internal Phase10SignedUpdates.Run(...)
// helper as its own independently runnable, filterable [Fact]. Identical assertions/messages
// via the shared LegacyAssert shim. Filter: --filter "FullyQualifiedName~Update".
public class UpdateTests
{
    [Fact]
    public void SignedUpdates_AllLegacyChecks() => Phase10SignedUpdates.Run(LegacyAssert.True);
}
