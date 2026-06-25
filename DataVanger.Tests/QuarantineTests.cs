using System;
using Xunit;
using DataVanger;
using DataVanger.Shared.Quarantine;

// Phase 09 decomposition — Secure Quarantine V2 (Phase 2 / Step 08).
// Faithful move: runs the unchanged internal Phase08SecureQuarantineV2.Run(...) helper
// (previously invoked inside the LegacyParityTests mega-[Fact]) as its own independently
// runnable, filterable [Fact]. Identical assertions/messages via the shared LegacyAssert
// shim. Filter: --filter "FullyQualifiedName~Quarantine".
public class QuarantineTests
{
    [Fact]
    public void SecureQuarantineV2_AllLegacyChecks() => Phase08SecureQuarantineV2.Run(LegacyAssert.True);

    // ── Phase 19 — restore result-message mapping (pure helper; no WPF, no security logic).
    // Proves failures are shown as refusals, items stay quarantined, and no secrets leak.

    [Fact]
    public void RestoreMessage_Success_SaysSuccess() =>
        Assert.Contains("sucesso", QuarantineRestoreMessages.Describe(QuarantineStatus.Success), StringComparison.OrdinalIgnoreCase);

    [Fact]
    public void RestoreMessage_IntegrityFailure_IsRefusal_AndKeepsQuarantined()
    {
        var m = QuarantineRestoreMessages.Describe(QuarantineStatus.IntegrityCheckFailed);
        Assert.Contains("recusada", m, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("permanece em quarentena", m, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("sucesso", m, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RestoreMessage_UnsafePath_IsRefusal() =>
        Assert.Contains("recusada", QuarantineRestoreMessages.Describe(QuarantineStatus.RestorePathInvalid), StringComparison.OrdinalIgnoreCase);

    [Fact]
    public void RestoreMessage_HashMismatch_IsRefusal() =>
        Assert.Contains("recusada", QuarantineRestoreMessages.Describe(QuarantineStatus.HashFailed), StringComparison.OrdinalIgnoreCase);

    [Fact]
    public void RestoreMessage_RecordNotFound_IsRefusal() =>
        Assert.Contains("recusada", QuarantineRestoreMessages.Describe(QuarantineStatus.RecordNotFound), StringComparison.OrdinalIgnoreCase);

    [Fact]
    public void RestoreMessage_PolicyDenied_IsRefusal() =>
        Assert.Contains("recusada", QuarantineRestoreMessages.Describe(QuarantineStatus.PolicyDenied), StringComparison.OrdinalIgnoreCase);

    [Fact]
    public void RestoreMessage_BoolFailure_KeepsQuarantined_AndIsNotSuccess()
    {
        var m = QuarantineRestoreMessages.DescribeBool(false);
        Assert.Contains("permanece em quarentena", m, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("sucesso", m, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RestoreMessage_NeverEmpty_AndNeverExposesSecrets()
    {
        foreach (QuarantineStatus s in Enum.GetValues(typeof(QuarantineStatus)))
        {
            var m = QuarantineRestoreMessages.Describe(s);
            Assert.False(string.IsNullOrWhiteSpace(m), $"Message for {s} must be non-empty.");
            Assert.DoesNotContain("key", m, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("hmac", m, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("stack", m, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("exception", m, StringComparison.OrdinalIgnoreCase);
        }
    }
}
