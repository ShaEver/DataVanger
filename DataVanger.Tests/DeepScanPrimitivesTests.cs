using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Classification;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;
using DataVanger.Detection;
using DataVanger.Engine;
using DataVanger.Memory;
using DataVanger.Memory.Readers;
using DataVanger.Memory.Rules;
using DataVanger.Reputation;
using static DataVanger.Tests.Fixtures.PeFactory;

// Phase 09 decomposition — Deep Scan primitives (RecursionGuard / FileTypeSniffer /
// StreamHasher), legacy sections 9, 11, 12. Faithful move: bare-statement bodies
// sliced verbatim into independently runnable, filterable [Fact]s; the private Assert
// shim delegates to LegacyAssert.True so condition AND message are preserved. These
// sections are self-contained (no cross-section locals).
// Filters: ~DeepScanPrimitives, ~RecursionGuard, ~FileTypeSniffer, ~StreamHasher.
public class DeepScanPrimitivesTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public void RecursionGuard_AllLegacyChecks()
    {
// 9. RecursionGuard
// ============================================================================

var rg = new DataVanger.Engine.DeepScan.RecursionGuard(maxDepth: 2, maxNestedArchives: 3);
Assert(rg.DepthAllowed(0) && rg.DepthAllowed(2),
    "RecursionGuard must admit depths up to the configured max.");
Assert(!rg.DepthAllowed(3),
    "RecursionGuard must reject depths beyond the configured max.");
Assert(rg.TryRegisterNestedArchive() && rg.TryRegisterNestedArchive() && rg.TryRegisterNestedArchive(),
    "RecursionGuard must admit nested archives up to the budget.");
Assert(!rg.TryRegisterNestedArchive(),
    "RecursionGuard must reject nested archives beyond the budget.");
Assert(rg.TryVisit("abc"),
    "RecursionGuard must register first-seen fingerprints.");
Assert(!rg.TryVisit("abc"),
    "RecursionGuard must reject repeat fingerprints (cycle protection).");
    }

    [Xunit.Fact]
    public void FileTypeSniffer_AllLegacyChecks()
    {
// 11. FileTypeSniffer magic-byte detection
// ============================================================================

byte[] mz = new byte[] { (byte)'M', (byte)'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00 };
Assert(DataVanger.Engine.DeepScan.FileTypeSniffer.SniffMagic(mz) == DataVanger.Engine.DeepScan.SniffedFileType.Pe,
    "Sniffer must detect MZ headers as PE.");
Assert(DataVanger.Engine.DeepScan.FileTypeSniffer.IsSpoofed(DataVanger.Engine.DeepScan.SniffedFileType.Pe, ".txt"),
    "Sniffer must flag PE bytes hiding in a .txt extension as spoofed.");
Assert(!DataVanger.Engine.DeepScan.FileTypeSniffer.IsSpoofed(DataVanger.Engine.DeepScan.SniffedFileType.Pe, ".exe"),
    "Sniffer must not flag MZ inside .exe as spoofed.");

byte[] zipHead = new byte[] { (byte)'P', (byte)'K', 0x03, 0x04, 0, 0, 0, 0 };
Assert(DataVanger.Engine.DeepScan.FileTypeSniffer.SniffMagic(zipHead) == DataVanger.Engine.DeepScan.SniffedFileType.ZipFamily,
    "Sniffer must detect PK\\x03\\x04 as a ZIP-family container.");
Assert(DataVanger.Engine.DeepScan.FileTypeSniffer.IsArchiveContainer(DataVanger.Engine.DeepScan.SniffedFileType.ZipFamily),
    "ZipFamily must be treated as an archive container.");
    }

    [Xunit.Fact]
    public async Task StreamHasher_AllLegacyChecks()
    {
// 12. StreamHasher correctness
// ============================================================================

byte[] payload = System.Text.Encoding.ASCII.GetBytes("hello world");
using (var ms = new MemoryStream(payload))
{
    var hash = await DataVanger.Engine.DeepScan.StreamHasher
        .ComputeSha256Async(ms, maxBytes: 0, CancellationToken.None);
    // sha256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    Assert(hash != null && hash.Equals("B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9", StringComparison.OrdinalIgnoreCase),
        "StreamHasher must compute the canonical SHA-256 of the payload.");
}
using (var ms = new MemoryStream(payload))
{
    var truncatedHash = await DataVanger.Engine.DeepScan.StreamHasher
        .ComputeSha256Async(ms, maxBytes: 4, CancellationToken.None);
    Assert(truncatedHash == null,
        "StreamHasher must return null when the payload exceeds the configured maxBytes.");
}
    }
}
