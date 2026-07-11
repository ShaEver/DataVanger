using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using DataVanger;
using DataVanger.Core;
using DataVanger.Engine.Quarantine;
using DataVanger.Infrastructure;
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
    public void RestoreMessage_StructuredFailure_KeepsQuarantined_AndIsNotSuccess()
    {
        var m = QuarantineRestoreMessages.Describe(QuarantineStatus.RestoreFailed);
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

    [Fact]
    public void ProductionAssembly_HasNoLegacyQuarantineManager_AndUsesV2Contracts()
    {
        Assert.Null(typeof(ScanEngine).Assembly.GetType("DataVanger.Core.QuarantineManager"));
        Assert.NotNull(typeof(ScanEngine).GetProperty(nameof(ScanEngine.Quarantine)));

        var constructor = Assert.Single(typeof(QuarantineWindow).GetConstructors());
        var parameters = constructor.GetParameters().Select(parameter => parameter.ParameterType).ToArray();
        Assert.Contains(typeof(IQuarantineService), parameters);
        Assert.Contains(typeof(IQuarantineIndex), parameters);
    }

    [Fact]
    public async Task ExpectedHashMismatch_IsRejected_AndOriginalRemains()
    {
        string source = Path.Combine(Path.GetTempPath(), "dvq-hash-" + Guid.NewGuid().ToString("N") + ".bin");
        await File.WriteAllTextAsync(source, "classified bytes");
        try
        {
            var service = NewService(new InMemoryQuarantineStore(), QuarantineOptions.Production());
            var result = await service.QuarantineAsync(new QuarantineRequest
            {
                SourcePath = source,
                Origin = QuarantineRequestOrigin.Automatic,
                Classification = QuarantineThreatClassification.ConfirmedMalware,
                ExpectedSha256 = new string('0', 64),
                DeleteOriginalAfterStore = true,
            });

            Assert.Equal(QuarantineStatus.HashFailed, result.Status);
            Assert.True(File.Exists(source));
        }
        finally
        {
            File.Delete(source);
        }
    }

    [Fact]
    public async Task MetadataPersistenceFailure_NeverRemovesOriginal()
    {
        string source = Path.Combine(Path.GetTempPath(), "dvq-persist-" + Guid.NewGuid().ToString("N") + ".bin");
        await File.WriteAllTextAsync(source, "must remain");
        try
        {
            var service = NewService(new RecordWriteFailingStore(), QuarantineOptions.Production());
            var result = await service.QuarantineAsync(new QuarantineRequest
            {
                SourcePath = source,
                Origin = QuarantineRequestOrigin.Automatic,
                Classification = QuarantineThreatClassification.ConfirmedMalware,
                DeleteOriginalAfterStore = true,
            });

            Assert.Equal(QuarantineStatus.MetadataWriteFailed, result.Status);
            Assert.True(File.Exists(source));
        }
        finally
        {
            File.Delete(source);
        }
    }

    [Theory]
    [InlineData(@"C:\safe\file.exe:stream")]
    [InlineData(@"C:\safe\sub\..\file.exe")]
    public void RestorePathPolicy_RejectsAdsAndTraversal(string destination)
    {
        var result = QuarantinePathPolicy.ValidateRestoreDestination(
            destination, @"C:\quarantine", QuarantineOptions.Production());
        Assert.False(result.IsValid);
    }

    [Fact]
    public void RestorePathPolicy_RejectsProtectedRoot()
    {
        var options = QuarantineOptions.Production();
        options.ForbiddenRestoreRoots.Add(@"C:\Program Files\DataVanger");
        var result = QuarantinePathPolicy.ValidateRestoreDestination(
            @"C:\Program Files\DataVanger\DataVanger.exe", @"C:\quarantine", options);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void LegacyInventory_IsUnauthenticatedAndHasNoRestoreSurface()
    {
        string root = Path.Combine(Path.GetTempPath(), "dvq-legacy-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            File.WriteAllText(Path.Combine(root, "quarantine_index.json"), "attacker-controlled");
            File.WriteAllBytes(Path.Combine(root, "legacy.quarantine"), new byte[] { 1, 2, 3 });
            var inventory = new LegacyQuarantineInventory(root);

            Assert.True(inventory.Inspect().HasUnauthenticatedItems);
            Assert.DoesNotContain(typeof(LegacyQuarantineInventory).GetMethods(),
                method => method.Name.Contains("Restore", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static QuarantineService NewService(IQuarantineStore store, QuarantineOptions options)
        => new(store, new QuarantineCryptoProvider(), new InMemoryQuarantineKeyProtector("p0-v2"), options);

    private sealed class RecordWriteFailingStore : IQuarantineStore
    {
        private readonly InMemoryQuarantineStore _inner = new();
        public Task WritePayloadAsync(string name, QuarantineEncryptedPayload payload, CancellationToken ct = default)
            => _inner.WritePayloadAsync(name, payload, ct);
        public Task<QuarantineEncryptedPayload?> ReadPayloadAsync(string name, CancellationToken ct = default)
            => _inner.ReadPayloadAsync(name, ct);
        public Task<bool> PayloadExistsAsync(string name, CancellationToken ct = default)
            => _inner.PayloadExistsAsync(name, ct);
        public Task WriteRecordAsync(QuarantineRecord record, byte[] metadata, byte[] tag, CancellationToken ct = default)
            => throw new IOException("simulated record persistence failure");
        public Task<QuarantineStoredRecord?> ReadRecordAsync(string id, CancellationToken ct = default)
            => _inner.ReadRecordAsync(id, ct);
        public Task<IReadOnlyList<string>> ListRecordIdsAsync(CancellationToken ct = default)
            => _inner.ListRecordIdsAsync(ct);
        public Task DeletePayloadAsync(string name, CancellationToken ct = default)
            => _inner.DeletePayloadAsync(name, ct);
    }
}
